import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Clock3, Download, KeyRound, Plus, RefreshCw, ScanSearch, ShieldCheck, Trash2, UserRound, UsersRound, WifiOff, X } from "lucide-react";
import { api, BridgeError, pickSaveFile } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import type {
  AccessCoverage,
  AccessGrant,
  AccessIdentity,
  AccessJobPollResponse,
  AccessPerson,
  AccessPollResponse,
  AccessScope,
  AccessServerView,
  AccessUnassigned,
} from "./types";

import {
  grantKey,
  phaseLabel,
  defaultRoleAccountName,
  type OnboardTargetChoice,
} from "./access-state";

function messageOf(error: unknown): string {
  return error instanceof BridgeError ? error.message : String(error);
}

function newOperationId(): string {
  return `op-${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(16)}`;
}

type Dialog =
  | { kind: "scan"; scope: AccessScope; approved: boolean; error: string | null; busy: boolean }
  | { kind: "identity"; identity?: AccessIdentity; name: string; fingerprints: string; shared: boolean; error: string | null; busy: boolean }
  | { kind: "attach"; item: AccessUnassigned; identityId: string; shared: boolean; error: string | null; busy: boolean }
  | { kind: "delete"; identity: AccessIdentity; confirmation: string; error: string | null; busy: boolean }
  | { kind: "offboard"; person: AccessPerson; grants: AccessGrant[]; confirmation: string; error: string | null; busy: boolean }
  | { kind: "onboard"; person: AccessPerson; targets: OnboardTargetChoice[]; publicKey: string; fingerprint: string; error: string | null; busy: boolean }
  | { kind: "rotate"; person: AccessPerson; grants: AccessGrant[]; oldFingerprint: string; publicKey: string; fingerprint: string; acknowledged: boolean; error: string | null; busy: boolean };

function Modal({ title, description, busy, onClose, children, footer }: { title: string; description: string; busy: boolean; onClose: () => void; children: ReactNode; footer: ReactNode }) {
  const ref = useModalFocus(onClose, "[data-access-first]", !busy);
  const titleId = `access-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-title`;
  const descriptionId = `${titleId}-description`;
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <div ref={ref} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId}>
        <header className="oars-modal-header">
          <div><h2 id={titleId}>{title}</h2><p id={descriptionId} className="oars-modal-subtitle">{description}</p></div>
        </header>
        <div className="oars-modal-body space-y-3">{children}</div>
        <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right">{footer}</div></footer>
      </div>
    </ApplicationOverlay>
  );
}

export function AccessTab() {
  const [scan, setScan] = useState<AccessPollResponse | null>(null);
  const [lastCompleted, setLastCompleted] = useState<AccessPollResponse | null>(null);
  const [identities, setIdentities] = useState<AccessIdentity[]>([]);
  const [selected, setSelected] = useState<Record<string, Set<string>>>({});
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<{ id: string; result: AccessJobPollResponse } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const scanTimer = useRef<number | null>(null);
  const jobTimer = useRef<number | null>(null);
  const scanGeneration = useRef(0);
  const jobGeneration = useRef(0);

  const clearScanTimer = useCallback(() => {
    if (scanTimer.current != null) window.clearTimeout(scanTimer.current);
    scanTimer.current = null;
  }, []);
  const clearJobTimer = useCallback(() => {
    if (jobTimer.current != null) window.clearTimeout(jobTimer.current);
    jobTimer.current = null;
  }, []);

  const loadIdentities = useCallback(async () => {
    const result = await api.access.identitiesList();
    setIdentities(result.identities);
    if (result.recovery_error) setError(`The identity registry was recovered: ${result.recovery_error}`);
  }, []);

  useEffect(() => {
    void loadIdentities().catch((failure) => setError(messageOf(failure)));
    return () => {
      scanGeneration.current += 1;
      jobGeneration.current += 1;
      clearScanTimer();
      clearJobTimer();
    };
  }, [clearJobTimer, clearScanTimer, loadIdentities]);

  const pollScan = useCallback((scanId: string, generation: number) => {
    const run = async () => {
      try {
        let result = await api.access.poll(scanId);
        if (scanGeneration.current !== generation) return;
        if (result.state !== "scanning") {
          const people = [...result.people_page.rows];
          let peopleOffset = people.length;
          while (peopleOffset < result.people_page.total) {
            const page = await api.access.poll(scanId, { peopleOffset, unassignedOffset: result.unassigned_page.total });
            if (scanGeneration.current !== generation) return;
            if (page.people_page.rows.length === 0) throw new Error("Access pagination stopped before all people were returned.");
            people.push(...page.people_page.rows);
            peopleOffset = people.length;
          }
          const unassigned = [...result.unassigned_page.rows];
          let unassignedOffset = unassigned.length;
          while (unassignedOffset < result.unassigned_page.total) {
            const page = await api.access.poll(scanId, { peopleOffset: result.people_page.total, unassignedOffset });
            if (scanGeneration.current !== generation) return;
            if (page.unassigned_page.rows.length === 0) throw new Error("Access pagination stopped before all unassigned keys were returned.");
            unassigned.push(...page.unassigned_page.rows);
            unassignedOffset = unassigned.length;
          }
          result = {
            ...result,
            people_page: { ...result.people_page, offset: 0, rows: people, has_more: false },
            unassigned_page: { ...result.unassigned_page, offset: 0, rows: unassigned, has_more: false },
          };
        }
        setScan(result);
        if (result.state === "scanning") scanTimer.current = window.setTimeout(run, 500);
        else if (result.state === "done") setLastCompleted(result);
      } catch (failure) {
        if (scanGeneration.current === generation) setError(messageOf(failure));
      }
    };
    void run();
  }, []);

  const pollJob = useCallback((jobId: string, generation: number) => {
    const run = async () => {
      try {
        const result = await api.access.jobPoll(jobId);
        if (jobGeneration.current !== generation) return;
        setJob({ id: jobId, result });
        if (result.state === "queued" || result.state === "running") jobTimer.current = window.setTimeout(run, 500);
        else {
          setNotice(result.state === "done" ? "The access job completed. Re-scan to verify the current fleet state." : "The access job finished with incomplete results. Review each item, then re-scan.");
          await loadIdentities();
        }
      } catch (failure) {
        if (jobGeneration.current === generation) setError(messageOf(failure));
      }
    };
    void run();
  }, [loadIdentities]);

  const startJob = useCallback((jobId: string) => {
    jobGeneration.current += 1;
    clearJobTimer();
    setJob({ id: jobId, result: { ok: true, state: "running", results: [] } });
    pollJob(jobId, jobGeneration.current);
  }, [clearJobTimer, pollJob]);

  const startScan = async (scope: AccessScope, approved: boolean) => {
    setDialog((current) => current?.kind === "scan" ? { ...current, busy: true, error: null } : current);
    setError(null);
    try {
      scanGeneration.current += 1;
      clearScanTimer();
      const result = await api.access.scan({ scope, approvedSensitiveRead: approved });
      setDialog(null);
      pollScan(result.scan_id, scanGeneration.current);
    } catch (failure) {
      setDialog((current) => current?.kind === "scan" ? { ...current, busy: false, error: messageOf(failure) } : current);
    }
  };

  const cancelScan = async () => {
    if (!scan || scan.state !== "scanning") return;
    await api.access.scanCancel(scan.scan_id);
    scanGeneration.current += 1;
    clearScanTimer();
    setScan(await api.access.poll(scan.scan_id));
  };

  const exportAudit = async (format: "csv" | "json") => {
    const snapshot = scan?.state === "done" ? scan : lastCompleted;
    if (!snapshot) return setError("Finish a scan before exporting its snapshot.");
    const path = await pickSaveFile("Export access audit", `oars-access-${snapshot.scan_id}.${format}`);
    if (!path) return;
    try {
      const result = await api.access.export({ format, scanId: snapshot.scan_id, path });
      setNotice(`Exported ${result.rows} audit rows to ${result.path}${result.formula_safe ? ". Spreadsheet fields are formula-safe." : ""}`);
    } catch (failure) {
      setError(messageOf(failure));
    }
  };

  const visibleScan = scan?.state === "done" ? scan : (lastCompleted ?? scan);
  const operationScan = visibleScan?.state === "done" ? visibleScan : null;
  const people = visibleScan?.people_page.rows ?? [];
  const unassigned = visibleScan?.unassigned_page.rows ?? [];
  const selectionFor = (identityId: string) => selected[identityId] ?? new Set<string>();
  const selectedGrants = (person: AccessPerson) => person.grants.filter((grant) => selectionFor(person.identity_id).has(grantKey(grant)));
  const buildOnboardTargets = (grants: AccessGrant[]): OnboardTargetChoice[] => (visibleScan?.servers ?? []).map((server) => {
    const selectedGrant = grants.find((grant) => grant.server_id === server.server_id);
    const accounts = server.accounts.filter((account) => !account.skipped).map((account) => account.user);
    return {
      serverId: server.server_id,
      serverName: server.name,
      enabled: Boolean(selectedGrant),
      kind: "account",
      name: selectedGrant?.user ?? server.connected_user ?? accounts[0] ?? "",
      accounts,
    };
  });
  const toggleGrant = (identityId: string, key: string, checked: boolean) => setSelected((current) => {
    const next = { ...current };
    const entries = new Set(next[identityId] ?? []);
    if (checked) entries.add(key); else entries.delete(key);
    next[identityId] = entries;
    return next;
  });

  const saveIdentity = async (current: Extract<Dialog, { kind: "identity" }>) => {
    const fingerprints = current.fingerprints.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    if (!current.name.trim() || fingerprints.length === 0) return setDialog({ ...current, error: "Enter a name and at least one SHA-256 fingerprint." });
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.access.identitiesSave({
        ...(current.identity ? { id: current.identity.id, revision: current.identity.revision } : {}),
        name: current.name.trim(),
        fingerprints,
        bindings: fingerprints.map((fingerprint) => ({ fingerprint, shared: current.shared })),
      });
      setDialog(null);
      await loadIdentities();
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const attachFingerprint = async (current: Extract<Dialog, { kind: "attach" }>) => {
    const identity = identities.find((item) => item.id === current.identityId);
    if (!identity) return setDialog({ ...current, error: "Select a person." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const fingerprints = [...identity.fingerprints, current.item.fingerprint];
      await api.access.identitiesSave({
        id: identity.id,
        revision: identity.revision,
        name: identity.name,
        fingerprints,
        bindings: [...identity.bindings, { fingerprint: current.item.fingerprint, shared: current.shared }],
      });
      setDialog(null);
      await loadIdentities();
      if (operationScan) pollScan(operationScan.scan_id, scanGeneration.current);
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const deleteIdentity = async (current: Extract<Dialog, { kind: "delete" }>) => {
    if (current.confirmation !== current.identity.name) return setDialog({ ...current, error: `Type “${current.identity.name}” to confirm.` });
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.access.identitiesDelete(current.identity.id, current.identity.revision, current.confirmation);
      setDialog(null);
      await loadIdentities();
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const offboard = async (current: Extract<Dialog, { kind: "offboard" }>) => {
    const identity = identities.find((item) => item.id === current.person.identity_id);
    if (!operationScan || !identity) return setDialog({ ...current, error: "The scan or identity changed. Re-scan and try again." });
    if (current.confirmation !== current.person.name) return setDialog({ ...current, error: `Type “${current.person.name}” to confirm.` });
    setDialog({ ...current, busy: true, error: null });
    try {
      const result = await api.access.offboard(identity.id, current.grants, { operationId: newOperationId(), scanId: operationScan.scan_id, identityRevision: identity.revision, confirmName: identity.name });
      setDialog(null);
      startJob(result.job_id);
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const inspectDialogKey = async (current: Extract<Dialog, { kind: "onboard" | "rotate" }>) => {
    if (!current.publicKey.trim()) return setDialog({ ...current, fingerprint: "", error: null });
    try {
      const result = await api.access.keyInspect(current.publicKey.trim());
      setDialog({ ...current, fingerprint: result.fingerprint, error: null });
    } catch (failure) { setDialog({ ...current, fingerprint: "", error: messageOf(failure) }); }
  };

  const onboard = async (current: Extract<Dialog, { kind: "onboard" }>) => {
    const identity = identities.find((item) => item.id === current.person.identity_id);
    if (!identity || !current.fingerprint) return setDialog({ ...current, error: "Inspect a valid public key first." });
    const targets = current.targets.filter((target) => target.enabled);
    if (targets.length === 0) return setDialog({ ...current, error: "Select at least one server target." });
    if (targets.some((target) => !/^[a-z0-9_][a-z0-9_-]{0,63}$/.test(target.name))) return setDialog({ ...current, error: "Each target needs a valid Linux account name." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const result = await api.access.onboard(identity.id, current.publicKey.trim(), targets.map((target) => ({ server_id: target.serverId, target: { kind: target.kind, name: target.name } })), { operationId: newOperationId(), identityRevision: identity.revision });
      setDialog(null);
      startJob(result.job_id);
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const rotate = async (current: Extract<Dialog, { kind: "rotate" }>) => {
    const identity = identities.find((item) => item.id === current.person.identity_id);
    if (!operationScan || !identity || !current.fingerprint || !current.acknowledged) return setDialog({ ...current, error: "Inspect the new key and acknowledge the destructive change." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const result = await api.access.rotate(identity.id, current.oldFingerprint, current.grants, current.publicKey.trim(), { operationId: newOperationId(), scanId: operationScan.scan_id, identityRevision: identity.revision });
      setDialog(null);
      startJob(result.job_id);
    } catch (failure) { setDialog({ ...current, busy: false, error: messageOf(failure) }); }
  };

  const coverage: AccessCoverage | null = visibleScan?.coverage ?? null;
  const metrics = visibleScan?.metrics;
  const privilegedSelected = dialog?.kind === "offboard" ? dialog.grants.filter((grant) => grant.sudo === "full").length : 0;
  const dialogPerson = dialog && (dialog.kind === "offboard" || dialog.kind === "onboard" || dialog.kind === "rotate") ? dialog.person : null;
  const statusText = useMemo(() => {
    if (!scan) return "No access snapshot";
    const scope = scan.scope === "all_login_accounts" ? "Full-account scope" : "Connected-account scope";
    if (scan.state === "scanning") return `Scanning · ${scope}`;
    if (scan.state === "canceled") return `Scan canceled · ${scope}`;
    return `${scope} · ${coverage === "complete" ? "complete for this scope" : "partial coverage"}`;
  }, [coverage, scan]);
  const attentionCount = (visibleScan?.sync_errors.length ?? 0) + (visibleScan?.source_warnings.length ?? 0);
  const lastScanText = visibleScan?.finished_at_ms
    ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(visibleScan.finished_at_ms))
    : "No completed scan";

  return (
    <div className="security-workspace access-workspace">
      <header className="security-commandbar">
        <div className="security-commandbar-copy">
          <span className={`security-commandbar-icon ${coverage === "partial" ? "is-warning" : ""}`}>{coverage === "complete" ? <ShieldCheck aria-hidden="true" /> : <ScanSearch aria-hidden="true" />}</span>
          <div><h2>Fleet access map</h2><p>{statusText} · Last finished {lastScanText}</p></div>
        </div>
        <div className="security-commandbar-actions">
          <Button variant="outline" onClick={() => setDialog({ kind: "identity", name: "", fingerprints: "", shared: false, error: null, busy: false })}><Plus />Add person</Button>
          <Button variant="outline" disabled={!operationScan} onClick={() => void exportAudit("csv")}><Download />CSV audit</Button>
          <Button variant="outline" disabled={!operationScan} onClick={() => void exportAudit("json")}><Download />JSON audit</Button>
          {scan?.state === "scanning" ? <Button variant="destructive" onClick={() => void cancelScan()}>Cancel scan</Button> : <Button onClick={() => setDialog({ kind: "scan", scope: visibleScan?.scope ?? "connected_accounts", approved: false, error: null, busy: false })}><RefreshCw />{visibleScan ? "Re-scan fleet" : "Scan fleet"}</Button>}
        </div>
      </header>

      {error && <div role="alert" className="security-message is-error"><AlertTriangle /><span>{error}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss error" onClick={() => setError(null)}><X /></Button></div>}
      {notice && <div role="status" className="security-message is-success"><CheckCircle2 /><span>{notice}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss message" onClick={() => setNotice(null)}><X /></Button></div>}

      {metrics && <section aria-label="Access summary" className="security-summary">
        <div><span>Known people</span><strong>{metrics.people}</strong><small>{identities.length} local identit{identities.length === 1 ? "y" : "ies"}</small></div>
        <div><span>Distinct keys</span><strong>{metrics.distinct_fingerprints}</strong><small>{unassigned.length} need{unassigned.length === 1 ? "s" : ""} an owner</small></div>
        <div><span>Fleet coverage</span><strong>{metrics.completed_servers}/{metrics.target_servers}</strong><small>{coverage === "complete" ? "Complete for this scope" : "Needs review"}</small></div>
        <div><span>Observed grants</span><strong>{metrics.observed_grants}</strong><small>Exact account and source matches</small></div>
      </section>}

      {(coverage === "partial" || attentionCount > 0) && <details className="security-attention" open>
        <summary><span className="security-attention-icon"><AlertTriangle /></span><span><strong>Coverage needs attention</strong><small>{attentionCount > 0 ? `${attentionCount} source or connection issue${attentionCount === 1 ? "" : "s"} limit this snapshot.` : "This scope has sources that Oars could not fully evaluate."}</small></span><span>Review details</span></summary>
        <div className="security-attention-list">
          {visibleScan?.sync_errors.map((item) => <div key={`sync-${item.server_id}`}><WifiOff /><span><strong>{item.server_id}</strong><small>{item.reason}</small></span></div>)}
          {visibleScan?.source_warnings.map((item) => <div key={`source-${item.server_id}-${item.reason}`}><KeyRound /><span><strong>{item.server_id}</strong><small>{item.reason}</small></span></div>)}
          {attentionCount === 0 && <div><ScanSearch /><span><strong>Partial source coverage</strong><small>Mutations apply only to observed grants. Missing or dynamic sources are not treated as clean.</small></span></div>}
        </div>
      </details>}

      {scan?.state === "scanning" && (
        <div
          className="security-progress"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={scan.metrics.target_servers}
          aria-valuenow={scan.metrics.completed_servers}
          aria-label="Fleet access scan progress"
          aria-valuetext={`Scanning ${scan.metrics.completed_servers} of ${scan.metrics.target_servers} servers`}
        >
          <span className="security-progress-icon"><RefreshCw className="is-spinning" /></span>
          <div>
            <strong>Scanning {scan.metrics.completed_servers} of {scan.metrics.target_servers} servers</strong>
            <p>The last completed snapshot stays visible while session workers inspect the fleet.</p>
          </div>
        </div>
      )}

      <div className="security-layout access-layout">
        <main className="security-panel access-people" aria-labelledby="access-people-title">
          <div className="security-panel-heading"><div><h3 id="access-people-title">People and access</h3><p>Choose exact account grants before you rotate, grant, or remove access.</p></div><span className="security-count">{people.length} mapped</span></div>
          {!visibleScan && <div className="security-empty"><ScanSearch /><h3>No fleet snapshot yet</h3><p>Scan connected accounts first, or approve a full-account scan when you need a broader audit.</p><Button onClick={() => setDialog({ kind: "scan", scope: "connected_accounts", approved: false, error: null, busy: false })}><ScanSearch />Scan fleet access</Button></div>}
          <div className="access-person-list">
            {people.map((person) => {
              const grants = selectedGrants(person);
              return <article key={person.identity_id} className="access-person-row">
                <header><span className="access-person-avatar"><UserRound /></span><div><h4>{person.name}</h4><p>{person.fingerprints.length} fingerprint{person.fingerprints.length === 1 ? "" : "s"} · {person.grants.length} observed grant{person.grants.length === 1 ? "" : "s"}</p></div><span className="security-status"><i className={person.grants.some((grant) => grant.sudo === "full") ? "is-warning" : ""} />{person.grants.some((grant) => grant.sudo === "full") ? "Privileged access" : "Standard access"}</span></header>
                <div className="access-grant-list">
                  {person.grants.map((grant) => <label key={grantKey(grant)} className="access-grant-row">
                    <input type="checkbox" checked={selectionFor(person.identity_id).has(grantKey(grant))} onChange={(event) => toggleGrant(person.identity_id, grantKey(grant), event.target.checked)} />
                    <span><strong>{grant.user}@{grant.server_name || grant.server_id}</strong><small>{grant.source_path}</small></span>
                    <span className={`access-policy policy-${grant.sudo}`}>{grant.sudo === "unknown" ? "Policy unknown" : grant.sudo === "none" ? "No sudo" : `${grant.sudo} sudo`}</span>
                  </label>)}
                </div>
                <footer>
                  <span>{grants.length === 0 ? "Grant uses its own fleet target picker" : `${grants.length} selected for rotation or removal`}</span>
                  <div><Button size="sm" variant="outline" disabled={!operationScan || (visibleScan?.servers.length ?? 0) === 0} onClick={() => setDialog({ kind: "onboard", person, targets: buildOnboardTargets(grants), publicKey: "", fingerprint: "", error: null, busy: false })}><Plus />Grant</Button>{person.fingerprints.map((fingerprint) => <Button key={fingerprint} size="sm" variant="outline" disabled={grants.length === 0} onClick={() => setDialog({ kind: "rotate", person, grants, oldFingerprint: fingerprint, publicKey: "", fingerprint: "", acknowledged: false, error: null, busy: false })}>Rotate</Button>)}<Button size="sm" variant="destructive" disabled={grants.length === 0} onClick={() => setDialog({ kind: "offboard", person, grants, confirmation: "", error: null, busy: false })}><Trash2 />{coverage === "partial" ? "Revoke observed" : "Offboard"}</Button></div>
                </footer>
              </article>;
            })}
          </div>
          {visibleScan && people.length === 0 && <div className="security-empty is-compact"><UsersRound /><h3>No keys match a known person</h3><p>Attach the unresolved fingerprints below, or add an identity with an exact SHA-256 fingerprint.</p></div>}
          {unassigned.length > 0 && <section className="unassigned-section" aria-labelledby="unassigned-title"><div className="unassigned-heading"><div><h3 id="unassigned-title">Keys without an owner</h3><p>Comments are labels only. Confirm who owns each exact fingerprint.</p></div><span>{unassigned.length} unresolved</span></div><div className="unassigned-list">{unassigned.map((item) => <article key={item.fingerprint}><span className="key-row-mark"><KeyRound /></span><div><code>{item.fingerprint}</code><p>{item.grants.map((grant) => `${grant.user}@${grant.server_name || grant.server_id}`).join(" · ")}</p></div><Button size="sm" variant="outline" onClick={() => setDialog({ kind: "attach", item, identityId: "", shared: false, error: null, busy: false })}>Assign owner</Button></article>)}</div></section>}
        </main>

        <aside className="security-rail">
          <section className="security-panel identity-panel"><div className="security-panel-heading"><div><h3>Identity registry</h3><p>Local names linked to exact fingerprints.</p></div><Button size="icon-sm" variant="ghost" aria-label="Refresh identities" onClick={() => void loadIdentities().catch((failure) => setError(messageOf(failure)))}><RefreshCw /></Button></div><div className="identity-list">{identities.map((identity) => <article key={identity.id}><span className="access-person-avatar"><UserRound /></span><div><strong>{identity.name}</strong><p>{identity.fingerprints.length} key{identity.fingerprints.length === 1 ? "" : "s"}</p></div><div><Button size="sm" variant="ghost" onClick={() => setDialog({ kind: "identity", identity, name: identity.name, fingerprints: identity.fingerprints.join("\n"), shared: identity.bindings.some((binding) => binding.shared), error: null, busy: false })}>Edit</Button><Button size="icon-sm" variant="ghost" aria-label={`Delete ${identity.name}`} onClick={() => setDialog({ kind: "delete", identity, confirmation: "", error: null, busy: false })}><Trash2 /></Button></div></article>)}{identities.length === 0 && <div className="security-empty is-compact"><UserRound /><h3>No saved identities</h3><p>Add a person to turn fingerprints into a useful access map.</p></div>}</div></section>
          <section className="security-panel fleet-panel"><div className="security-panel-heading"><div><h3>Fleet coverage</h3><p>Current scan state by server.</p></div></div><div className="fleet-list">{(scan?.servers ?? []).map((server: AccessServerView) => <article key={server.server_id}><span className={`security-status-dot state-${server.phase}`} /><div><strong>{server.name}</strong><p>{server.coverage_reason || server.error || `${server.accounts.length} accounts checked`}</p></div><span>{phaseLabel(server.phase)}</span></article>)}{!scan && <div className="security-empty is-compact"><ScanSearch /><h3>Waiting for a scan</h3><p>Server progress will appear here.</p></div>}</div></section>
          {job && <section className="security-panel job-panel"><div className="security-panel-heading"><div><h3>Access job</h3><p>Remote changes and recovery state.</p></div><span className="security-status"><i className={job.result.state === "done" ? "is-success" : job.result.state === "partial" ? "is-warning" : ""} />{job.result.state}</span></div><div className="job-list">{job.result.results.map((item, index) => <article key={`${item.server_id}-${item.user}-${item.source_path}-${index}`}><span>{item.state === "done" ? <CheckCircle2 /> : <Clock3 />}</span><div><strong>{item.user}@{item.server_id}</strong><p>{item.error || item.source_path || phaseLabel(item.state)}</p></div></article>)}</div>{(job.result.state === "queued" || job.result.state === "running") && <Button className="job-cancel" size="sm" variant="outline" onClick={() => void api.access.jobCancel(job.id)}>Cancel queued changes</Button>}</section>}
        </aside>
      </div>

      {dialog?.kind === "scan" && <Modal title="Scan fleet access" description="Choose the audit scope. Coverage is always stated for this exact scope." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button data-access-first onClick={() => void startScan(dialog.scope, dialog.approved)} disabled={dialog.busy || (dialog.scope === "all_login_accounts" && !dialog.approved)}>Start scan</Button></>}>
        <label className="block text-sm font-medium">Scope<OarsSelect data-access-first className="mt-1" value={dialog.scope} onValueChange={(scope) => setDialog({ ...dialog, scope: scope as AccessScope, approved: false })} options={[{ value: "connected_accounts", label: "Connected login accounts" }, { value: "all_login_accounts", label: "All login accounts" }]} /></label>
        {dialog.scope === "all_login_accounts" && <label className="flex gap-2 rounded-md border p-3 text-sm"><input type="checkbox" checked={dialog.approved} onChange={(event) => setDialog({ ...dialog, approved: event.target.checked })} /><span>I approve reads of other users’ SSH key files and sudo policy on the selected fleet.</span></label>}
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </Modal>}

      {dialog?.kind === "identity" && <Modal title={dialog.identity ? "Edit person" : "Add person"} description="Names are local labels. Exact decoded-key fingerprints define identity." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void saveIdentity(dialog)} disabled={dialog.busy}>Save person</Button></>}>
        <label className="block text-sm font-medium">Name<input data-access-first className="border-input bg-background mt-1 w-full rounded-md border px-3 py-2" value={dialog.name} onChange={(event) => setDialog({ ...dialog, name: event.target.value })} /></label>
        <label className="block text-sm font-medium">SHA-256 fingerprints<textarea className="border-input bg-background mt-1 min-h-24 w-full rounded-md border px-3 py-2 font-mono text-xs" value={dialog.fingerprints} onChange={(event) => setDialog({ ...dialog, fingerprints: event.target.value })} /></label>
        <label className="flex gap-2 text-sm"><input type="checkbox" checked={dialog.shared} onChange={(event) => setDialog({ ...dialog, shared: event.target.checked })} /><span>Allow these exact fingerprints to be attached to another person. Shared access can make ownership ambiguous.</span></label>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </Modal>}

      {dialog?.kind === "attach" && <Modal title="Attach unassigned key" description="The key comment is a label only. Select the person who owns this exact fingerprint." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void attachFingerprint(dialog)} disabled={dialog.busy}>Attach key</Button></>}>
        <p className="break-all rounded-md border p-2 font-mono text-xs">{dialog.item.fingerprint}</p><label className="block text-sm font-medium">Person<OarsSelect data-access-first className="mt-1" value={dialog.identityId} onValueChange={(identityId) => setDialog({ ...dialog, identityId })} options={[{ value: "", label: "Select a person" }, ...identities.map((identity) => ({ value: identity.id, label: identity.name }))]} /></label><label className="flex gap-2 text-sm"><input type="checkbox" checked={dialog.shared} onChange={(event) => setDialog({ ...dialog, shared: event.target.checked })} />Allow this fingerprint to be shared.</label>{dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </Modal>}

      {dialog?.kind === "delete" && <Modal title={`Delete ${dialog.identity.name}?`} description="This deletes the local label only. It does not remove remote access." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep person</Button><Button variant="destructive" onClick={() => void deleteIdentity(dialog)} disabled={dialog.busy || dialog.confirmation !== dialog.identity.name}>Delete local label</Button></>}><label className="block text-sm font-medium">Type {dialog.identity.name} to confirm<input data-access-first className="border-input bg-background mt-1 w-full rounded-md border px-3 py-2" value={dialog.confirmation} onChange={(event) => setDialog({ ...dialog, confirmation: event.target.value })} /></label>{dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}</Modal>}

      {dialog?.kind === "offboard" && <Modal title={coverage === "partial" ? "Revoke observed grants" : `Offboard ${dialog.person.name}`} description={`${dialog.grants.length} exact grants are selected, including ${privilegedSelected} with full sudo. ${coverage === "partial" ? "This partial snapshot cannot prove fleet-wide removal." : "Oars will validate every scanned file and line before it writes."}`} busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep access</Button><Button variant="destructive" onClick={() => void offboard(dialog)} disabled={dialog.busy || dialog.confirmation !== dialog.person.name}>Remove selected grants</Button></>}><div className="rounded-md border p-2 text-xs">{dialog.grants.map((grant) => <div key={grantKey(grant)}>{grant.user}@{grant.server_name || grant.server_id} · {grant.source_path}</div>)}</div><label className="block text-sm font-medium">Type {dialog.person.name} to confirm<input data-access-first className="border-input bg-background mt-1 w-full rounded-md border px-3 py-2" value={dialog.confirmation} onChange={(event) => setDialog({ ...dialog, confirmation: event.target.value })} /></label>{dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}</Modal>}

      {dialog?.kind === "onboard" && dialogPerson && <Modal title={`Grant access for ${dialogPerson.name}`} description="Choose each server and its target account or read-only SFTP role. The fingerprint binding is saved before remote work starts." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void onboard(dialog)} disabled={dialog.busy || !dialog.fingerprint || !dialog.targets.some((target) => target.enabled)}>Grant access</Button></>}>
        <div className="access-target-matrix">
          {dialog.targets.map((target, targetIndex) => <section key={target.serverId} className={target.enabled ? "access-target-row is-enabled" : "access-target-row"}>
            <label className="access-target-server"><input data-access-first={targetIndex === 0 ? true : undefined} type="checkbox" checked={target.enabled} onChange={(event) => setDialog({ ...dialog, targets: dialog.targets.map((item) => item.serverId === target.serverId ? { ...item, enabled: event.target.checked } : item) })} /><span><strong>{target.serverName}</strong><small>{target.serverId}</small></span></label>
            <label>Target type<OarsSelect disabled={!target.enabled} value={target.kind} onValueChange={(value) => { const kind = value as OnboardTargetChoice["kind"]; setDialog({ ...dialog, targets: dialog.targets.map((item) => item.serverId === target.serverId ? { ...item, kind, name: kind === "account" ? (item.accounts[0] ?? "") : defaultRoleAccountName(dialog.person.name) } : item) }); }} options={[{ value: "account", label: "Existing account" }, { value: "read_only_role", label: "Read-only SFTP role" }]} /></label>
            {target.kind === "account" && target.accounts.length > 0 ? <label>Login account<OarsSelect disabled={!target.enabled} value={target.name} onValueChange={(name) => setDialog({ ...dialog, targets: dialog.targets.map((item) => item.serverId === target.serverId ? { ...item, name } : item) })} options={target.accounts.map((account) => ({ value: account, label: account }))} /></label> : <label>{target.kind === "account" ? "Login account" : "Role account"}<input disabled={!target.enabled} value={target.name} placeholder={target.kind === "account" ? "No scanned account" : "reports-readonly"} onChange={(event) => setDialog({ ...dialog, targets: dialog.targets.map((item) => item.serverId === target.serverId ? { ...item, name: event.target.value } : item) })} /></label>}
          </section>)}
        </div>
        <label className="block text-sm font-medium">Public key<textarea className="border-input bg-background mt-1 min-h-24 w-full rounded-md border px-3 py-2 font-mono text-xs" value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, fingerprint: "" })} onBlur={() => void inspectDialogKey(dialog)} /></label>{dialog.fingerprint && <p className="break-all text-xs"><strong>Fingerprint:</strong> {dialog.fingerprint}</p>}{dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </Modal>}

      {dialog?.kind === "rotate" && dialogPerson && <Modal title={`Rotate key for ${dialogPerson.name}`} description={`Add and verify the new key on ${dialog.grants.length} targets before Oars removes the old observed grants. A re-scan is required before rotation is complete.`} busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button variant="destructive" onClick={() => void rotate(dialog)} disabled={dialog.busy || !dialog.fingerprint || !dialog.acknowledged}>Start rotation</Button></>}><div className="rounded-md border p-2 text-xs"><p className="break-all"><strong>Old:</strong> {dialog.oldFingerprint}</p>{dialog.grants.map((grant) => <div key={grantKey(grant)}>{grant.user}@{grant.server_name || grant.server_id} · {grant.source_path}</div>)}</div><label className="block text-sm font-medium">New public key<textarea data-access-first className="border-input bg-background mt-1 min-h-24 w-full rounded-md border px-3 py-2 font-mono text-xs" value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, fingerprint: "" })} onBlur={() => void inspectDialogKey(dialog)} /></label>{dialog.fingerprint && <p className="break-all text-xs"><strong>New fingerprint:</strong> {dialog.fingerprint}</p>}<label className="flex gap-2 rounded-md border border-destructive/30 p-3 text-sm"><input type="checkbox" checked={dialog.acknowledged} onChange={(event) => setDialog({ ...dialog, acknowledged: event.target.checked })} /><span>I understand that this changes remote SSH access and that partial failures keep both identity bindings until a verified re-scan.</span></label>{dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}</Modal>}
    </div>
  );
}
