import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  FileKey2,
  FolderOpen,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCw,
  ShieldCheck,
  Trash2,
  UserRoundCog,
  Wrench,
  X,
} from "lucide-react";
import { api, BridgeError, pickFile, pickSaveFile, vault } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import {
  SshJobController,
  SshSnapshotController,
  accountLabel,
  attentionItems,
  canMutateSource,
  canPlanRoles,
  formatMode,
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
  type JobView,
  type KeysTransport,
  type SnapshotView,
} from "./keys-state";
import type {
  SshAccountRef,
  SshDeployKey,
  SshInspectResponse,
  SshKeyEntry,
  SshRole,
  SshRoleKind,
  SshRolePlanResponse,
  SshSnapshotPollResponse,
  SshSource,
} from "./types";

type KeysDialog =
  | { kind: "add"; publicKey: string; comment: string; sourcePath: string; inspected: SshInspectResponse | null; busy: boolean; error: string | null }
  | { kind: "generate"; destination: string; comment: string; passphrase: string; remember: boolean; busy: boolean; error: string | null }
  | { kind: "rotate"; entry: SshKeyEntry; publicKey: string; inspected: SshInspectResponse | null; busy: boolean; error: string | null }
  | { kind: "rotate-verify"; method: "local" | "external"; path: string; passphrase: string; confirm: string; busy: boolean; error: string | null }
  | { kind: "revoke"; entry: SshKeyEntry; confirm: string; busy: boolean; error: string | null }
  | { kind: "role-create"; name: string; roleKind: SshRoleKind; plan: SshRolePlanResponse | null; publicKey: string; busy: boolean; error: string | null }
  | { kind: "role-repair"; role: SshRole; plan: SshRolePlanResponse | null; busy: boolean; error: string | null }
  | { kind: "role-delete"; role: SshRole; confirm: string; plan: SshRolePlanResponse | null; busy: boolean; error: string | null }
  | { kind: "deploy-generate"; label: string; comment: string; busy: boolean; error: string | null }
  | { kind: "deploy-delete"; entry: SshDeployKey; confirm: string; busy: boolean; error: string | null }
  | { kind: "deploy-result"; label: string; publicKey: string; path: string };

function messageOf(error: unknown): string {
  return error instanceof BridgeError ? error.message : String(error);
}

function KeyModal({ title, description, busy, onClose, children, footer }: { title: string; description: string; busy: boolean; onClose: () => void; children: ReactNode; footer: ReactNode }) {
  const ref = useModalFocus(onClose, "[data-key-first]", !busy);
  const titleId = `keys-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-title`;
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <div ref={ref} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={`${titleId}-description`}>
        <header className="oars-modal-header oars-modal-title-row">
          <span className="oars-modal-icon"><KeyRound aria-hidden="true" /></span>
          <div><h2 id={titleId}>{title}</h2><p id={`${titleId}-description`} className="oars-modal-subtitle">{description}</p></div>
          <Button className="oars-modal-close" type="button" variant="ghost" size="icon-sm" aria-label="Close dialog" onClick={onClose} disabled={busy}><X /></Button>
        </header>
        <div className="oars-modal-body">{children}</div>
        <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right">{footer}</div></footer>
      </div>
    </ApplicationOverlay>
  );
}

// What to do when the tracked job reaches a terminal state.
type PendingAction =
  | { kind: "notice"; success: string }
  | { kind: "generate"; passphrase: string; remember: boolean }
  | { kind: "deploy-generated"; label: string };

export function KeysTab({ serverId }: { serverId: string }) {
  const transportRef = useRef<KeysTransport | null>(null);
  if (!transportRef.current) {
    transportRef.current = {
      snapshot: (id, account) => api.sshkeys.snapshot(id, account),
      snapshotPoll: (id) => api.sshkeys.snapshotPoll(id),
      jobPoll: (id) => api.sshkeys.jobPoll(id),
      jobCancel: (id) => api.sshkeys.jobCancel(id),
    };
  }
  const controllersRef = useRef<{ snapshots: SshSnapshotController; jobs: SshJobController } | null>(null);
  if (!controllersRef.current) {
    controllersRef.current = {
      snapshots: new SshSnapshotController(transportRef.current),
      jobs: new SshJobController(transportRef.current),
    };
  }
  const controllers = controllersRef.current;

  const [snapView, setSnapView] = useState<SnapshotView>(controllers.snapshots.current);
  const [jobView, setJobView] = useState<JobView | null>(controllers.jobs.current);
  const [account, setAccount] = useState<SshAccountRef>({ kind: "connected" });
  const [dialog, setDialog] = useState<KeysDialog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const pendingAction = useRef<PendingAction | null>(null);
  const pendingRotate = useRef<{ jobId: string; newFingerprint: string } | null>(null);

  useEffect(() => {
    controllers.snapshots.subscribe(setSnapView);
    controllers.jobs.subscribe(setJobView);
    controllers.jobs.onWaiting = (view) => {
      if (pendingRotate.current?.jobId === view.jobId) {
        setDialog({ kind: "rotate-verify", method: "local", path: "", passphrase: "", confirm: "", busy: false, error: null });
      }
    };
    controllers.jobs.onTerminal = (view) => {
      const action = pendingAction.current;
      pendingAction.current = null;
      if (view.result.state === "done") {
        if (action?.kind === "generate") {
          const result = view.result.result;
          const plan = keychainStoragePlan(action.remember, action.passphrase, result);
          if (plan.store && plan.account && plan.secret) {
            vault.set(plan.account, plan.secret).catch(() => {
              setError("The key pair was created, but the passphrase could not be stored in the Keychain. Store it manually.");
            });
          }
          if (result?.public_key) {
            setNotice(`A local key pair was created at ${result.private_path ?? "the chosen path"}. Review the public key before you install it.`);
            setDialog({ kind: "add", publicKey: result.public_key, comment: "", sourcePath: "", inspected: null, busy: false, error: null });
          } else {
            setNotice("The local key pair was created.");
          }
        } else if (action?.kind === "deploy-generated") {
          const result = view.result.result;
          if (result?.public_key) {
            setDialog({ kind: "deploy-result", label: action.label, publicKey: result.public_key, path: result.private_path ?? "" });
          }
          setNotice(`The deploy key for ${action.label} was created.`);
        } else if (action?.kind === "notice") {
          setNotice(view.result.result?.idempotent ? "This public key was already present in the selected source. No changes were made." : action.success);
        }
        controllers.snapshots.refresh();
      } else if (view.result.state === "partial") {
        const failedStep = view.result.steps.find((step) => step.state === "error" || step.state === "conflict");
        setError(failedStep?.error ?? "The job finished with problems; review the steps and refresh.");
        controllers.snapshots.refresh();
      }
    };
    return () => {
      controllers.snapshots.stop();
      controllers.jobs.stop();
    };
  }, [controllers]);

  useEffect(() => {
    controllers.snapshots.start(serverId, account);
  }, [controllers, serverId, account]);

  // The completed view: the fresh snapshot when it has finished, otherwise
  // the last completed one (stale-while-refresh). Mutations stay bound to
  // the snapshot that produced the visible data, so they pause while a
  // refresh is in flight.
  const completed = snapView.latest && (snapView.latest.state === "done" || snapView.latest.state === "partial") ? snapView.latest : null;
  const snapshot = completed ?? snapView.lastCompleted;
  const mutationsReady = completed !== null && !snapView.polling && snapView.snapshotId !== null;
  const snapshotId = mutationsReady ? snapView.snapshotId : null;

  const accountKeys = useMemo(() => (snapshot ? snapshot.keys.filter((entry) => entry.parsed) : []), [snapshot]);
  const sources = useMemo(() => snapshot?.sources ?? [], [snapshot]);
  const staticSourcesList = useMemo(() => (snapshot ? staticSources(snapshot) : []), [snapshot]);
  const mutableSources = useMemo(() => staticSourcesList.filter(canMutateSource), [staticSourcesList]);
  const attention = useMemo(() => (snapshot ? attentionItems(snapshot) : []), [snapshot]);
  const roles = useMemo(() => snapshot?.roles ?? [], [snapshot]);
  const deployKeys = useMemo(() => snapshot?.deploy_keys ?? [], [snapshot]);
  const accounts = useMemo(() => (snapshot ? selectableAccounts(snapshot.roles) : [{ kind: "connected" } as SshAccountRef]), [snapshot]);

  const copyText = async (value: string, success: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(success);
    } catch {
      setError("Oars could not copy to the clipboard. Select and copy the value manually.");
    }
  };

  const trackJob = (jobId: string, label: string, action?: PendingAction) => {
    if (action) pendingAction.current = action;
    controllers.jobs.track(jobId, label);
  };

  const inspectKey = (publicKey: string, comment: string | undefined): Promise<SshInspectResponse> => {
    return api.sshkeys.inspect(publicKey, comment && comment.length > 0 ? comment : undefined);
  };

  const addKey = async (current: Extract<KeysDialog, { kind: "add" }>) => {
    if (!snapshot || !snapshotId) return setDialog({ ...current, error: "Take a snapshot before adding keys." });
    const sourcePath = current.sourcePath || mutableSources[0]?.path || "";
    const source = sourceByPath(snapshot, sourcePath);
    if (!source || !canMutateSource(source) || !source.file_sha256) {
      return setDialog({ ...current, error: "No writable authorized_keys source is available in this snapshot." });
    }
    let inspected = current.inspected;
    if (!inspected) {
      if (!current.publicKey.trim()) return setDialog({ ...current, error: "Paste a complete OpenSSH public key." });
      setDialog({ ...current, busy: true, error: null });
      try {
        inspected = await inspectKey(current.publicKey.trim(), current.comment.trim() || undefined);
      } catch (failure) {
        setDialog({ ...current, busy: false, error: messageOf(failure) });
        return;
      }

      setDialog({ ...current, inspected, busy: false, error: null });
      return;
    }
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.add({
        operationId: newOperationId(),
        snapshotId,
        sourcePath,
        fileSha256: source.file_sha256,
        publicKey: current.publicKey.trim(),
        comment: current.comment.trim() || undefined,
      });
      setDialog(null);
      trackJob(started.job_id, `Add key ${started.fingerprint}`, { kind: "notice", success: "The public key was added." });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const generateKey = async (current: Extract<KeysDialog, { kind: "generate" }>) => {
    if (!current.destination.trim()) return setDialog({ ...current, error: "Choose where to save the local private key." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.localGenerate({
        operationId: newOperationId(),
        destination: current.destination.trim(),
        comment: current.comment.trim() || undefined,
        passphrase: current.passphrase || undefined,
      });
      setDialog(null);
      trackJob(started.job_id, "Generate a local key pair", { kind: "generate", passphrase: current.passphrase, remember: current.remember });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const rotateKey = async (current: Extract<KeysDialog, { kind: "rotate" }>) => {
    if (!snapshot || !snapshotId) return setDialog({ ...current, error: "Take a snapshot before rotating keys." });
    const source = sourceByPath(snapshot, current.entry.source_path);
    if (!source?.file_sha256) return setDialog({ ...current, error: "The source is no longer writable; refresh the snapshot." });
    let inspected = current.inspected;
    if (!inspected) {
      if (!current.publicKey.trim()) return setDialog({ ...current, error: "Paste the replacement public key." });
      setDialog({ ...current, busy: true, error: null });
      try {
        inspected = await inspectKey(current.publicKey.trim(), undefined);
      } catch (failure) {
        setDialog({ ...current, busy: false, error: messageOf(failure) });
        return;
      }
      if (inspected.fingerprint === keyFingerprint(current.entry)) {
        setDialog({ ...current, inspected: null, busy: false, error: "The replacement key is the same as the current key." });
        return;
      }
      setDialog({ ...current, inspected, busy: false, error: null });
      return;
    }
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.rotate({
        operationId: newOperationId(),
        snapshotId,
        sourcePath: current.entry.source_path,
        fileSha256: source.file_sha256,
        oldFingerprint: keyFingerprint(current.entry),
        lineHash: current.entry.line_hash,
        newPublicKey: current.publicKey.trim(),
      });
      setDialog(null);
      pendingRotate.current = { jobId: started.job_id, newFingerprint: started.new_fingerprint };
      trackJob(started.job_id, "Rotate the key in two safe stages", { kind: "notice", success: "The key was rotated." });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const commitRotation = async (current: Extract<KeysDialog, { kind: "rotate-verify" }>) => {
    const pending = pendingRotate.current;
    if (!pending) return setDialog(null);
    setDialog({ ...current, busy: true, error: null });
    try {
      if (current.method === "local") {
        if (!current.path.trim()) {
          setDialog({ ...current, busy: false, error: "Choose the new private key on this Mac." });
          return;
        }
        await api.sshkeys.rotateCommit(pending.jobId, {
          kind: "local_private_key",
          path: current.path.trim(),
          ...(current.passphrase ? { passphrase: current.passphrase } : {}),
        });
      } else {
        if (current.confirm.trim() !== pending.newFingerprint) {
          setDialog({ ...current, busy: false, error: "The typed fingerprint does not match the staged key." });
          return;
        }
        await api.sshkeys.rotateCommit(pending.jobId, { kind: "external_confirmation", confirm_fingerprint: current.confirm.trim() });
      }
      setDialog(null);
      // The commit re-queues the job; resume polling until it finishes.
      controllers.jobs.track(pending.jobId, "Finish the rotation");
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const keepBothRotationKeys = () => {
    pendingRotate.current = null;
    setDialog(null);
    void controllers.jobs.cancelActive();
  };

  const revokeKey = async (current: Extract<KeysDialog, { kind: "revoke" }>) => {
    if (!snapshot || !snapshotId) return setDialog({ ...current, error: "Take a snapshot before revoking keys." });
    const source = sourceByPath(snapshot, current.entry.source_path);
    if (!source?.file_sha256) return setDialog({ ...current, error: "The source is no longer writable; refresh the snapshot." });
    const needsConfirm = revokeNeedsConfirmation(current.entry, account, accountKeys);
    if (needsConfirm && current.confirm.trim() !== keyFingerprint(current.entry)) {
      return setDialog({ ...current, error: "Type the full fingerprint to confirm this revocation." });
    }
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.revoke({
        operationId: newOperationId(),
        snapshotId,
        sourcePath: current.entry.source_path,
        fileSha256: source.file_sha256,
        fingerprint: keyFingerprint(current.entry),
        lineHash: current.entry.line_hash,
        ...(needsConfirm ? { confirmFingerprint: current.confirm.trim() } : {}),
      });
      setDialog(null);
      trackJob(started.job_id, `Revoke ${keyFingerprint(current.entry)}`, { kind: "notice", success: "The key was revoked. Existing sessions can stay open." });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const commitRolePlan = async (plan: SshRolePlanResponse, publicKey: string | undefined, success: string, onError: (message: string) => void, onDone: () => void) => {
    try {
      const started = await api.sshkeys.rolesCommit(newOperationId(), plan.plan_id, publicKey);
      onDone();
      trackJob(started.job_id, `Apply the role plan for ${plan.account}`, { kind: "notice", success });
    } catch (failure) {
      onError(messageOf(failure));
    }
  };

  const deployGenerate = async (current: Extract<KeysDialog, { kind: "deploy-generate" }>) => {
    if (!current.label.trim()) return setDialog({ ...current, error: "Name the repository or service this key is for." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.deployKeysGenerate({
        operationId: newOperationId(),
        serverId,
        repositoryLabel: current.label.trim(),
        comment: current.comment.trim() || undefined,
      });
      setDialog(null);
      trackJob(started.job_id, `Generate a deploy key for ${current.label.trim()}`, { kind: "deploy-generated", label: current.label.trim() });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const deployDelete = async (current: Extract<KeysDialog, { kind: "deploy-delete" }>) => {
    if (current.confirm.trim() !== current.entry.fingerprint) {
      return setDialog({ ...current, error: "Type the full fingerprint to confirm this deletion." });
    }
    setDialog({ ...current, busy: true, error: null });
    try {
      const started = await api.sshkeys.deployKeysDelete({
        operationId: newOperationId(),
        serverId,
        deployKeyId: current.entry.deploy_key_id,
        confirmFingerprint: current.confirm.trim(),
      });
      setDialog(null);
      trackJob(started.job_id, `Delete the deploy key for ${current.entry.repository_label}`, { kind: "notice", success: "The deploy key was deleted from the server." });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const keyActionsReady = (entry: SshKeyEntry): boolean => {
    if (!mutationsReady || !snapshot) return false;
    const source = sourceByPath(snapshot, entry.source_path);
    return Boolean(source && canMutateSource(source));
  };

  if (!snapshot && snapView.polling && !snapView.error) {
    return <OarsLoadingState title="Reading SSH access" detail="Oars is evaluating the server's key sources and managed roles." />;
  }

  return (
    <div className="security-workspace keys-workspace">
      <header className="security-commandbar">
        <div className="security-commandbar-copy">
          <span className="security-commandbar-icon"><KeyRound aria-hidden="true" /></span>
          <div><h2>SSH access keys</h2><p>Control the public keys, managed roles, and deploy keys for this server.</p></div>
        </div>
        <div className="security-commandbar-actions">
          <Button variant="outline" onClick={() => setDialog({ kind: "deploy-generate", label: "", comment: "", busy: false, error: null })} disabled={!snapshot}><FileKey2 />New deploy key</Button>
          <Button variant="outline" onClick={() => setDialog({ kind: "generate", destination: "", comment: "oars-generated", passphrase: "", remember: false, busy: false, error: null })}><FolderOpen />Generate local key</Button>
          <Button onClick={() => setDialog({ kind: "add", publicKey: "", comment: "", sourcePath: mutableSources[0]?.path ?? "", inspected: null, busy: false, error: null })} disabled={!mutationsReady || mutableSources.length === 0}><Plus />Add public key</Button>
        </div>
      </header>

      {snapView.polling && snapshot && <OarsRefreshStatus label="Refreshing the snapshot" />}
      {error && <div className="security-message is-error" role="alert"><AlertTriangle /><span>{error}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss error" onClick={() => setError(null)}><X /></Button></div>}
      {notice && <div className="security-message is-success" role="status"><CheckCircle2 /><span>{notice}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss message" onClick={() => setNotice(null)}><X /></Button></div>}
      {snapView.error && <div className="security-message is-error" role="alert"><AlertTriangle /><span>{snapView.disconnected ? "The SSH session was lost. Reconnect, then refresh." : snapView.error}</span><Button variant="outline" size="sm" onClick={() => controllers.snapshots.refresh()}><RefreshCw />Retry</Button></div>}

      {snapshot && (
        <section className="security-summary" aria-label="Key inventory summary">
          <div><span>Authorized keys</span><strong>{accountKeys.length}</strong><small>{accountLabel(account)}</small></div>
          <div><span>Needs attention</span><strong>{attention.length}</strong><small>{attention.length === 0 ? "Nothing unusual" : "Sources, rows, or roles"}</small></div>
          <div><span>Managed roles</span><strong>{roles.length}</strong><small>{roles.filter((role) => role.kind === "read_only_sftp").length} read-only SFTP</small></div>
          <div><span>Deploy keys</span><strong>{deployKeys.length}</strong><small>Server-side Git identities</small></div>
        </section>
      )}

      {snapshot && (
        <div className="keys-context">
          <label className="keys-account">
            <span>Account</span>
            <OarsSelect
              value={account.kind === "managed_role" ? `role:${account.name ?? ""}` : "connected"}
              onValueChange={(value) => {
                setAccount(value === "connected" ? { kind: "connected" } : { kind: "managed_role", name: value.slice(5) });
              }}
              options={accounts.map((option) => {
                const value = option.kind === "managed_role" ? `role:${option.name ?? ""}` : "connected";
                return { value, label: accountLabel(option) };
              })}
            />
          </label>
          <span className="keys-context-meta">
            {snapshot.coverage === "partial" ? "Partial coverage" : snapshot.scope === "effective_policy" ? "Effective sshd policy" : "Single source"} · {snapshotTimeText(snapshot.finished_at_ms)}
          </span>
          <Button variant="ghost" size="sm" onClick={() => controllers.snapshots.refresh()} disabled={snapView.polling}><RefreshCw className={snapView.polling ? "is-spinning" : ""} />Refresh</Button>
        </div>
      )}

      {attention.length > 0 && (
        <section className="security-panel keys-attention" aria-labelledby="keys-attention-title">
          <div className="security-panel-heading"><div><h3 id="keys-attention-title">Needs attention</h3><p>These items limit what Oars can show or change.</p></div></div>
          <div className="security-list">
            {attention.map((item) => (
              <article className="key-row is-malformed" key={item.id}>
                <div className="key-row-mark"><AlertTriangle aria-hidden="true" /></div>
                <div className="key-row-copy"><div className="key-row-title"><strong>{item.title}</strong></div><p>{item.detail}</p></div>
              </article>
            ))}
          </div>
        </section>
      )}

      {jobView && (
        <section className="security-panel keys-job" aria-labelledby="keys-job-title">
          <div className="security-panel-heading">
            <div><h3 id="keys-job-title">{jobView.label}</h3><p>{jobView.cancelRequested ? "Cancel requested — waiting for the server" : jobStateLabel(jobView.result.state)}</p></div>
            {(jobView.result.state === "queued" || jobView.result.state === "running" || jobView.result.state === "waiting_for_verification") && (
              <Button variant="outline" size="sm" disabled={jobView.cancelRequested} onClick={() => void controllers.jobs.cancelActive()}>{jobView.cancelRequested ? "Cancel requested" : jobView.result.state === "waiting_for_verification" ? "Keep both keys" : "Cancel"}</Button>
            )}
            {(jobView.result.state === "done" || jobView.result.state === "partial" || jobView.result.state === "canceled") && (
              <Button variant="ghost" size="sm" onClick={() => controllers.jobs.dismiss()}>Dismiss</Button>
            )}
          </div>
          {jobView.pollError && <p className="security-message is-error" role="alert">Could not refresh job status: {jobView.pollError}. Oars will retry.</p>}
          <div className="keys-job-steps">
            {jobView.result.steps.map((step) => (
              <div className={`keys-job-step is-${step.state}`} key={step.id}>
                <span className="security-status"><i className={step.state === "done" ? "is-success" : step.state === "error" || step.state === "conflict" ? "is-warning" : ""} />{stepStateLabel(step.state)}</span>
                <div><strong>{jobStepLabel(step.id)}</strong>{step.error && <p>{step.error}</p>}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="security-layout keys-layout">
        <main className="security-panel keys-inventory" aria-labelledby="authorized-keys-title">
          <div className="security-panel-heading">
            <div><h3 id="authorized-keys-title">Authorized keys</h3><p>Every action is bound to the exact file and line that Oars read.</p></div>
          </div>
          {!snapshot && snapView.error && <div className="security-empty"><AlertTriangle /><h3>No snapshot available</h3><p>Reconnect to the server and refresh to read its key sources.</p></div>}
          {snapshot && sources.length === 0 && <div className="security-empty"><KeyRound /><h3>No key sources</h3><p>The snapshot did not find an authorized_keys source for this account.</p></div>}
          {snapshot && sources.map((source) => {
            const sourceKeys = snapshot.keys.filter((entry) => entry.source_path === source.path);
            const mutable = mutationsReady && canMutateSource(source);
            const mode = formatMode(source.mode);
            return (
              <section className="keys-source" key={source.path} aria-label={source.path}>
                <header className="keys-source-heading">
                  <div><code>{source.path}</code><p>{sourceStatusLabel(source)}{mode ? ` · mode ${mode}` : ""}{source.owner ? ` · ${source.owner}` : ""}</p></div>
                  <span className="security-status"><i className={source.status === "readable" ? "is-success" : source.status === "missing" ? "" : "is-warning"} />{sourceStatusLabel(source)}</span>
                </header>
                <div className="security-list">
                  {sourceKeys.map((entry) => entry.parsed ? (
                    <article className="key-row" key={`${entry.source_path}-${entry.line_index}-${entry.line_hash}`}>
                      <div className="key-row-mark"><KeyRound aria-hidden="true" /></div>
                      <div className="key-row-copy">
                        <div className="key-row-title"><strong>{entry.comment || "Unlabeled public key"}</strong><span>{entry.type ?? "SSH key"}{entry.bits ? ` · ${entry.bits} bit` : ""}</span></div>
                        <code title={keyFingerprint(entry)}>{keyFingerprint(entry)}</code>
                        <p>{entry.policy_assessment ? `${policyLabel(entry.policy_assessment.level)} — ${entry.policy_assessment.detail}` : "No key-level restrictions"}</p>
                      </div>
                      <div className="key-row-actions">
                        <Button variant="ghost" size="icon-sm" aria-label={`Copy fingerprint for ${entry.comment || "key"}`} onClick={() => void copyText(keyFingerprint(entry), "The fingerprint was copied.")}><Copy /></Button>
                        <Button variant="outline" size="sm" disabled={!keyActionsReady(entry)} onClick={() => setDialog({ kind: "rotate", entry, publicKey: "", inspected: null, busy: false, error: null })}><RotateCw />Rotate</Button>
                        <Button variant="destructive" size="sm" disabled={!keyActionsReady(entry)} onClick={() => setDialog({ kind: "revoke", entry, confirm: "", busy: false, error: null })}><Trash2 />Revoke</Button>
                      </div>
                    </article>
                  ) : (
                    <article className="key-row is-malformed" key={`${entry.source_path}-${entry.line_index}-${entry.line_hash}`}>
                      <div className="key-row-mark"><AlertTriangle aria-hidden="true" /></div>
                      <div className="key-row-copy"><div className="key-row-title"><strong>Malformed entry</strong><span>Line {entry.line_index + 1}</span></div><code>{entry.raw}</code><p>{entry.error || "This line could not be parsed and cannot be changed safely."}</p></div>
                    </article>
                  ))}
                  {sourceKeys.length === 0 && (
                    <div className="security-empty is-compact">
                      <KeyRound />
                      <h3>{source.status === "missing" ? "Not created yet" : source.status === "readable" ? "No keys in this file" : "Contents unknown"}</h3>
                      <p>{source.status === "missing" ? "Adding a key creates this file with safe permissions." : source.status === "readable" ? "This file is empty. Add a key when you are ready to allow SSH access." : "Oars could not read this file, so its keys are unknown and no change is allowed."}</p>
                      {mutable && <Button size="sm" onClick={() => setDialog({ kind: "add", publicKey: "", comment: "", sourcePath: source.path, inspected: null, busy: false, error: null })}><Plus />Add public key</Button>}
                    </div>
                  )}
                </div>
              </section>
            );
          })}
        </main>

        <aside className="keys-rail">
          <section className="security-panel roles-panel" aria-labelledby="managed-roles-title">
            <div className="security-panel-heading">
              <div><h3 id="managed-roles-title">Managed roles</h3><p>Dedicated accounts with a verified access policy.</p></div>
              <Button variant="outline" size="sm" disabled={!snapshot || !canPlanRoles(snapshot)} onClick={() => setDialog({ kind: "role-create", name: "", roleKind: "read_only_sftp", plan: null, publicKey: "", busy: false, error: null })}><Plus />Create role</Button>
            </div>
            {snapshot && !canPlanRoles(snapshot) && <p className="keys-rail-hint">Role changes need root or approved sudo on this server.</p>}
            <div className="role-list">
              {roles.map((role) => (
                <article className="role-row" key={role.name}>
                  <span className="role-row-icon">{role.kind === "read_only_sftp" ? <ShieldCheck /> : <UserRoundCog />}</span>
                  <div>
                    <strong>{role.name}</strong>
                    <p>{roleKindLabel(role)} · {role.key_fingerprints.length} key{role.key_fingerprints.length === 1 ? "" : "s"} · {rolePolicyLabel(role.policy_state)}</p>
                  </div>
                  <div className="role-row-actions">
                    {roleNeedsRepair(role) && <Button variant="outline" size="icon-sm" aria-label={`Repair role ${role.name}`} onClick={() => setDialog({ kind: "role-repair", role, plan: null, busy: false, error: null })}><Wrench /></Button>}
                    <Button variant="ghost" size="icon-sm" aria-label={`Delete role ${role.name}`} onClick={() => setDialog({ kind: "role-delete", role, confirm: "", plan: null, busy: false, error: null })}><Trash2 /></Button>
                  </div>
                </article>
              ))}
              {roles.length === 0 && snapshot && <div className="security-empty is-compact"><UserRoundCog /><h3>No managed roles</h3><p>Create a dedicated account when access should not use the connected login.</p></div>}
            </div>
          </section>

          <section className="security-panel deploy-panel" aria-labelledby="deploy-keys-title">
            <div className="security-panel-heading">
              <div><h3 id="deploy-keys-title">Deploy keys</h3><p>Server-side identities for Git automation.</p></div>
            </div>
            <div className="role-list">
              {deployKeys.map((entry) => (
                <article className="role-row" key={entry.deploy_key_id}>
                  <span className="role-row-icon"><FileKey2 /></span>
                  <div>
                    <strong>{entry.repository_label}</strong>
                    <p>{entry.fingerprint}</p>
                  </div>
                  <div className="role-row-actions">
                    <Button variant="ghost" size="icon-sm" aria-label={`Copy fingerprint for ${entry.repository_label}`} onClick={() => void copyText(entry.fingerprint, "The fingerprint was copied.")}><Copy /></Button>
                    <Button variant="ghost" size="icon-sm" aria-label={`Delete deploy key for ${entry.repository_label}`} onClick={() => setDialog({ kind: "deploy-delete", entry, confirm: "", busy: false, error: null })}><Trash2 /></Button>
                  </div>
                </article>
              ))}
              {deployKeys.length === 0 && snapshot && <div className="security-empty is-compact"><FileKey2 /><h3>No deploy keys</h3><p>Generate a server-side key pair when a repository needs pull access.</p></div>}
            </div>
          </section>
        </aside>
      </div>

      {dialog?.kind === "add" && (
        <KeyModal
          title="Add a public key"
          description={`Oars validates the key, then appends one exact line to ${dialog.sourcePath || "the selected source"}.`}
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            <Button data-key-first onClick={() => void addKey(dialog)} disabled={dialog.busy || (!dialog.inspected && !dialog.publicKey.trim())}>
              {dialog.inspected ? "Add key" : "Review key"}
            </Button>
          </>}
        >
          {mutableSources.length > 1 && (
            <label className="security-field"><span>Target source</span>
              <OarsSelect value={dialog.sourcePath} onValueChange={(sourcePath) => setDialog({ ...dialog, sourcePath, inspected: null })} options={mutableSources.map((source) => ({ value: source.path, label: source.path }))} />
            </label>
          )}
          <label className="security-field"><span>OpenSSH public key</span><textarea data-key-first value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, inspected: null, error: null })} placeholder="ssh-ed25519 AAAAC3… person@device" /></label>
          <label className="security-field"><span>Display comment <small>Optional</small></span><input value={dialog.comment} onChange={(event) => setDialog({ ...dialog, comment: event.target.value, inspected: null })} placeholder="person@device" /></label>
          {dialog.inspected && (
            <div className="security-resource"><KeyRound /><div><span>{dialog.inspected.key_type}{dialog.inspected.bits ? ` · ${dialog.inspected.bits} bit` : ""}</span><code>{dialog.inspected.fingerprint}</code></div></div>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "generate" && (
        <KeyModal
          title="Generate a local key"
          description="The private key never leaves this Mac. Oars verifies both files, then offers the public half for installation."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            <Button data-key-first onClick={() => void generateKey(dialog)} disabled={dialog.busy || !dialog.destination.trim()}>Generate key pair</Button>
          </>}
        >
          <div className="security-field"><span>Private key location</span><div className="security-input-action"><input data-key-first value={dialog.destination} onChange={(event) => setDialog({ ...dialog, destination: event.target.value })} placeholder="Choose a local file" /><Button type="button" variant="outline" onClick={() => void pickSaveFile("Save the local private key", "id_ed25519").then((destination) => { if (destination) setDialog({ ...dialog, destination }); })}><FolderOpen />Choose</Button></div></div>
          <label className="security-field"><span>Key comment</span><input value={dialog.comment} onChange={(event) => setDialog({ ...dialog, comment: event.target.value })} /></label>
          <label className="security-field"><span>Passphrase <small>Optional</small></span><input type="password" value={dialog.passphrase} onChange={(event) => setDialog({ ...dialog, passphrase: event.target.value })} autoComplete="new-password" /></label>
          {dialog.passphrase.length > 0 && (
            <label className="keys-check"><input type="checkbox" checked={dialog.remember} onChange={(event) => setDialog({ ...dialog, remember: event.target.checked })} /><span>Remember the passphrase in the macOS Keychain</span></label>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "rotate" && (
        <KeyModal
          title="Rotate this public key"
          description="Oars installs the new key next to the old one, then asks you to prove access before the old key is removed."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            <Button data-key-first onClick={() => void rotateKey(dialog)} disabled={dialog.busy || (!dialog.inspected && !dialog.publicKey.trim())}>
              {dialog.inspected ? "Stage the new key" : "Review replacement"}
            </Button>
          </>}
        >
          <div className="security-resource"><KeyRound /><div><span>Current fingerprint</span><code>{keyFingerprint(dialog.entry)}</code></div></div>
          <label className="security-field"><span>Replacement public key</span><textarea data-key-first value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, inspected: null, error: null })} placeholder="ssh-ed25519 AAAAC3… person@device" /></label>
          {dialog.inspected && (
            <div className="security-resource"><RotateCw /><div><span>Replacement · {dialog.inspected.key_type}{dialog.inspected.bits ? ` · ${dialog.inspected.bits} bit` : ""}</span><code>{dialog.inspected.fingerprint}</code></div></div>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "rotate-verify" && (
        <KeyModal
          title="Prove the new key works"
          description="The old key stays on the server until the new key signs in once. Nothing is lost if you stop here."
          busy={dialog.busy}
          onClose={keepBothRotationKeys}
          footer={<>
            <Button variant="outline" onClick={keepBothRotationKeys} disabled={dialog.busy}>Keep both keys</Button>
            <Button data-key-first onClick={() => void commitRotation(dialog)} disabled={dialog.busy}>Verify and remove the old key</Button>
          </>}
        >
          <fieldset className="security-choice"><legend>Verification method</legend>
            <label><input type="radio" checked={dialog.method === "local"} onChange={() => setDialog({ ...dialog, method: "local" })} /><span><strong>Sign in with a local private key</strong><small>Oars opens a temporary session with the new key.</small></span></label>
            <label><input type="radio" checked={dialog.method === "external"} onChange={() => setDialog({ ...dialog, method: "external" })} /><span><strong>I signed in elsewhere</strong><small>Type the new fingerprint after a successful sign-in.</small></span></label>
          </fieldset>
          {dialog.method === "local" ? (
            <>
              <div className="security-field"><span>Private key on this Mac</span><div className="security-input-action"><input data-key-first value={dialog.path} onChange={(event) => setDialog({ ...dialog, path: event.target.value })} placeholder="~/.ssh/id_ed25519" /><Button type="button" variant="outline" onClick={() => void pickFile("Choose the private key").then((path) => { if (path) setDialog({ ...dialog, path }); })}><FolderOpen />Choose</Button></div></div>
              <label className="security-field"><span>Passphrase <small>Optional</small></span><input type="password" value={dialog.passphrase} onChange={(event) => setDialog({ ...dialog, passphrase: event.target.value })} autoComplete="off" /></label>
            </>
          ) : (
            <label className="security-field"><span>New key fingerprint</span><input data-key-first value={dialog.confirm} onChange={(event) => setDialog({ ...dialog, confirm: event.target.value, error: null })} placeholder={pendingRotate.current?.newFingerprint ?? "SHA256:…"} /></label>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "revoke" && (
        <KeyModal
          title="Revoke this public key?"
          description="New SSH connections with this key stop working. Existing sessions can stay open."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep key</Button>
            <Button variant="destructive" data-key-first onClick={() => void revokeKey(dialog)} disabled={dialog.busy}>Revoke key</Button>
          </>}
        >
          <div className="security-resource is-danger"><Trash2 /><div><span>{dialog.entry.comment || "Unlabeled public key"}</span><code>{keyFingerprint(dialog.entry)}</code></div></div>
          {revokeNeedsConfirmation(dialog.entry, account, accountKeys) && (
            <label className="security-field"><span>Type the full fingerprint to confirm</span><input data-key-first value={dialog.confirm} onChange={(event) => setDialog({ ...dialog, confirm: event.target.value, error: null })} placeholder="SHA256:…" /></label>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "role-create" && (
        <KeyModal
          title="Create a managed role"
          description="Oars creates a dedicated Linux account and records its access policy."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            {!dialog.plan && <Button data-key-first disabled={dialog.busy || !dialog.name.trim()} onClick={() => {
              setDialog({ ...dialog, busy: true, error: null });
              api.sshkeys.rolesPlan(serverId, dialog.name.trim(), dialog.roleKind, "create")
                .then((plan) => setDialog({ ...dialog, plan, busy: false, error: null }))
                .catch((failure) => setDialog({ ...dialog, busy: false, error: messageOf(failure) }));
            }}>Preview plan</Button>}
            {dialog.plan && <Button data-key-first disabled={dialog.busy || !dialog.publicKey.trim()} onClick={() => {
              const plan = dialog.plan;
              if (!plan) return;
              setDialog({ ...dialog, busy: true, error: null });
              void commitRolePlan(plan, dialog.publicKey.trim(), `The role ${plan.account} was created.`, (message) => setDialog({ ...dialog, busy: false, error: message }), () => setDialog(null));
            }}>Create role</Button>}
          </>}
        >
          {!dialog.plan && (
            <>
              <label className="security-field"><span>Linux account name</span><input data-key-first value={dialog.name} onChange={(event) => setDialog({ ...dialog, name: event.target.value, error: null })} placeholder="deploy-readonly" /></label>
              <fieldset className="security-choice"><legend>Access policy</legend>
                <label><input type="radio" checked={dialog.roleKind === "read_only_sftp"} onChange={() => setDialog({ ...dialog, roleKind: "read_only_sftp" })} /><span><strong>Read-only SFTP</strong><small>File listing and download through a forced command. No shell.</small></span></label>
                <label><input type="radio" checked={dialog.roleKind === "standard_ssh"} onChange={() => setDialog({ ...dialog, roleKind: "standard_ssh" })} /><span><strong>Standard SSH</strong><small>A normal login account with shell access.</small></span></label>
              </fieldset>
            </>
          )}
          {dialog.plan && (
            <>
              <div className="security-resource"><UserRoundCog /><div><span>{dialog.plan.account} · {dialog.plan.home ?? "account"}</span><code>{dialog.plan.commands.join(" && ") || "No privileged commands"}</code></div></div>
              <ul className="keys-effects">{dialog.plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul>
              <label className="security-field"><span>First approved public key</span><textarea data-key-first value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, error: null })} placeholder="ssh-ed25519 AAAAC3… person@device" /></label>
            </>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "role-repair" && (
        <KeyModal
          title={`Repair the policy for ${dialog.role.name}?`}
          description="Oars re-verifies the account and managed policy. For read-only roles, it also reapplies the approved forced-SFTP restrictions to every parsed installed key."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            {!dialog.plan && <Button data-key-first disabled={dialog.busy} onClick={() => {
              setDialog({ ...dialog, busy: true, error: null });
              api.sshkeys.rolesPlan(serverId, dialog.role.name, dialog.role.kind, "repair")
                .then((plan) => setDialog({ ...dialog, plan, busy: false, error: null }))
                .catch((failure) => setDialog({ ...dialog, busy: false, error: messageOf(failure) }));
            }}>Preview repair</Button>}
            {dialog.plan && <Button data-key-first disabled={dialog.busy} onClick={() => {
              const plan = dialog.plan;
              if (!plan) return;
              setDialog({ ...dialog, busy: true, error: null });
              void commitRolePlan(plan, undefined, `The policy for ${plan.account} was repaired.`, (message) => setDialog({ ...dialog, busy: false, error: message }), () => setDialog(null));
            }}>Repair policy</Button>}
          </>}
        >
          <div className="security-resource is-danger"><Wrench /><div><span>{roleKindLabel(dialog.role)}</span><code>{rolePolicyLabel(dialog.role.policy_state)}</code></div></div>
          {dialog.plan && <ul className="keys-effects">{dialog.plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul>}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "role-delete" && (
        <KeyModal
          title={`Delete ${dialog.role.name}?`}
          description="Oars removes the Linux account and its policy. The home directory is left on disk."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep role</Button>
            {!dialog.plan && <Button variant="destructive" data-key-first disabled={dialog.busy || dialog.confirm.trim() !== dialog.role.name} onClick={() => {
              setDialog({ ...dialog, busy: true, error: null });
              api.sshkeys.rolesPlan(serverId, dialog.role.name, dialog.role.kind, "delete")
                .then((plan) => setDialog({ ...dialog, plan, busy: false, error: null }))
                .catch((failure) => setDialog({ ...dialog, busy: false, error: messageOf(failure) }));
            }}>Preview deletion</Button>}
            {dialog.plan && <Button variant="destructive" data-key-first disabled={dialog.busy} onClick={() => {
              const plan = dialog.plan;
              if (!plan) return;
              setDialog({ ...dialog, busy: true, error: null });
              void commitRolePlan(plan, undefined, `The role ${plan.account} was deleted.`, (message) => setDialog({ ...dialog, busy: false, error: message }), () => setDialog(null));
            }}>Delete role</Button>}
          </>}
        >
          <div className="security-resource is-danger"><Trash2 /><div><span>{roleKindLabel(dialog.role)}</span><code>{dialog.role.name}</code></div></div>
          {!dialog.plan && (
            <label className="security-field"><span>Type the account name to confirm</span><input data-key-first value={dialog.confirm} onChange={(event) => setDialog({ ...dialog, confirm: event.target.value, error: null })} placeholder={dialog.role.name} /></label>
          )}
          {dialog.plan && (
            <>
              <div className="security-resource"><UserRoundCog /><div><span>Privileged command</span><code>{dialog.plan.commands.join(" && ") || "No privileged commands"}</code></div></div>
              <ul className="keys-effects">{dialog.plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul>
            </>
          )}
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "deploy-generate" && (
        <KeyModal
          title="Generate a deploy key"
          description="Oars creates an Ed25519 pair on the server with no passphrase, ready for unattended Git access."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button>
            <Button data-key-first onClick={() => void deployGenerate(dialog)} disabled={dialog.busy || !dialog.label.trim()}>Generate deploy key</Button>
          </>}
        >
          <label className="security-field"><span>Repository or service</span><input data-key-first value={dialog.label} onChange={(event) => setDialog({ ...dialog, label: event.target.value, error: null })} placeholder="acme/shopfront" /></label>
          <label className="security-field"><span>Comment <small>Optional</small></span><input value={dialog.comment} onChange={(event) => setDialog({ ...dialog, comment: event.target.value })} /></label>
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "deploy-delete" && (
        <KeyModal
          title={`Delete the deploy key for ${dialog.entry.repository_label}?`}
          description="Git automation using this key loses access. The public key in the repository settings becomes harmless."
          busy={dialog.busy}
          onClose={() => setDialog(null)}
          footer={<>
            <Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep key</Button>
            <Button variant="destructive" data-key-first onClick={() => void deployDelete(dialog)} disabled={dialog.busy || dialog.confirm.trim() !== dialog.entry.fingerprint}>Delete deploy key</Button>
          </>}
        >
          <div className="security-resource is-danger"><FileKey2 /><div><span>{dialog.entry.repository_label}</span><code>{dialog.entry.fingerprint}</code></div></div>
          <label className="security-field"><span>Type the full fingerprint to confirm</span><input data-key-first value={dialog.confirm} onChange={(event) => setDialog({ ...dialog, confirm: event.target.value, error: null })} placeholder="SHA256:…" /></label>
          {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
        </KeyModal>
      )}

      {dialog?.kind === "deploy-result" && (
        <KeyModal
          title="Deploy key ready"
          description="Add this public key as a deploy key in the repository settings (Settings → Deploy keys on GitHub)."
          busy={false}
          onClose={() => setDialog(null)}
          footer={<Button data-key-first onClick={() => setDialog(null)}>Done</Button>}
        >
          <div className="security-resource"><FileKey2 /><div><span>{dialog.label}</span><code>{dialog.path}</code></div></div>
          <label className="security-field"><span>Public key</span><textarea readOnly value={dialog.publicKey} onFocus={(event) => event.target.select()} /></label>
          <Button variant="outline" onClick={() => void copyText(dialog.publicKey, "The public key was copied.")}><Copy />Copy public key</Button>
        </KeyModal>
      )}
    </div>
  );
}
