import { useCallback, useEffect, useRef, useState } from "react";
import { api, BridgeError, vault } from "./bridge";
import type { BackupJob, BackupRunStatus } from "./types";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import { AlertTriangle, Plus, RefreshCw, X } from "lucide-react";

function humanSchedule(j: BackupJob): string {
  const s = j.schedule;
  if (!s.enabled || s.mode === "manual") return "Manual";
  if (s.mode === "interval") return `Every ${s.interval_every} ${s.interval_unit}`;
  return `Cron: ${s.expr}`;
}

function destLabel(j: BackupJob): string {
  const d = j.destination;
  const prefix = d.prefix ? `/${d.prefix.replace(/^\/+|\/+$/g, "")}` : "";
  return `${d.bucket}${prefix} (${d.provider}) · ${j.transfer}`;
}

type EditorDraft = {
  id?: string;
  revision?: number;
  name: string;
  source_path: string;
  provider: string;
  bucket: string;
  prefix: string;
  endpoint: string;
  region: string;
  use_iam: boolean;
  storage_class: string;
  transfer: "copy" | "sync";
  schedule_mode: "manual" | "interval" | "custom";
  interval_unit: "hours" | "days";
  interval_every: number;
  expr: string;
  enabled: boolean;
  access_key: string;
  secret_key: string;
};

function jobToDraft(j: BackupJob): EditorDraft {
  return {
    id: j.id,
    revision: j.revision as number | undefined,
    name: j.name,
    source_path: j.source_path,
    provider: j.destination.provider,
    bucket: j.destination.bucket,
    prefix: j.destination.prefix,
    endpoint: j.destination.endpoint,
    region: j.destination.region,
    use_iam: j.destination.use_iam,
    storage_class: j.destination.storage_class,
    transfer: j.transfer as EditorDraft["transfer"],
    schedule_mode: j.schedule.mode as EditorDraft["schedule_mode"],
    interval_unit: j.schedule.interval_unit as EditorDraft["interval_unit"],
    interval_every: j.schedule.interval_every,
    expr: j.schedule.expr,
    enabled: j.schedule.enabled,
    access_key: "",
    secret_key: "",
  };
}

function emptyDraft(): EditorDraft {
  return {
    name: "",
    source_path: "/var/www",
    provider: "minio",
    bucket: "",
    prefix: "",
    endpoint: "http://127.0.0.1:9000",
    region: "",
    use_iam: false,
    storage_class: "standard",
    transfer: "copy",
    schedule_mode: "manual",
    interval_unit: "hours",
    interval_every: 24,
    expr: "0 2 * * *",
    enabled: false,
    access_key: "",
    secret_key: "",
  };
}

export function BackupsTab({ serverId }: { serverId: string }) {
  const [jobs, setJobs] = useState<BackupJob[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<EditorDraft | null>(null);
  const [editingJob, setEditingJob] = useState<BackupJob | null>(null);
  const [runStatus, setRunStatus] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [historyCounts, setHistoryCounts] = useState<Record<string, number>>({});
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const genRef = useRef(0);

  const load = useCallback(async () => {
    const gen = ++genRef.current;
    setLoading(true);
    try {
      const r = await api.backup.list(serverId);
      if (gen !== genRef.current) return;
      setJobs((r.jobs ?? []) as BackupJob[]);
      setError((r as { recovery_error?: string }).recovery_error ?? null);
    } catch (e) {
      if (gen !== genRef.current) return;
      const be = e instanceof BridgeError ? e : null;
      setError(be ? `${be.code}: ${be.message}` : String(e));
    } finally {
      if (gen === genRef.current) {
        setHasLoaded(true);
        setLoading(false);
      }
    }
  }, [serverId]);

  useEffect(() => {
    void load();
    return () => { genRef.current++; };
  }, [load]);

  // Clear secret state on server change / unmount (NEXT-SPEC secrets).
  useEffect(() => () => {
    if (editing) {
      setEditing((prev) => prev ? { ...prev, access_key: "", secret_key: "" } : null);
    }
  }, [serverId]);

  const handleSave = async () => {
    if (!editing) return;
    if (!editing.name.trim() || !editing.source_path.trim()) {
      setError("Name and source path required");
      return;
    }
    if (!editing.bucket.trim() && !editing.use_iam) {
      setError("Bucket required");
      return;
    }
    try {
      const jobInput: import("./types").BackupJobInput = {
        id: editing.id,
        expected_revision: editing.revision,
        server_id: serverId,
        name: editing.name.trim(),
        source_path: editing.source_path.trim(),
        destination: {
          type: "s3",
          provider: editing.provider as import("./types").BackupProvider,
          bucket: editing.bucket.trim(),
          prefix: editing.prefix.trim(),
          endpoint: editing.endpoint.trim(),
          region: editing.region.trim(),
          use_iam: editing.use_iam,
          storage_class: editing.storage_class.trim() || "standard",
        },
        transfer: editing.transfer,
        schedule: {
          mode: editing.schedule_mode,
          interval_unit: editing.interval_unit,
          interval_every: editing.interval_every,
          expr: editing.expr.trim(),
          enabled: editing.enabled,
        },
      };
      // Non-IAM scheduled jobs need credentials disclosure -> store transiently via Keychain
      // and send approved_remote_secret. For now, require explicit approval via confirm.
      const needsSecret = !editing.use_iam && editing.enabled && editing.schedule_mode !== "manual";
      const creds = !editing.use_iam && (editing.access_key || editing.secret_key)
        ? { access_key: editing.access_key, secret_key: editing.secret_key }
        : undefined;
      if (needsSecret && !creds && !editing.id) {
        setError("Scheduled non-IAM jobs need access/secret keys (stored as backup:<job_id> before save).");
        return;
      }
      // For new jobs, we don't yet know job id for Keychain; save first, then store if needed.
      // Use legacy save path until plan/operation flow is wired to a coordinator.
      await api.backup.save(jobInput, creds);
      // If credentials were supplied without a known job id, fetch the new job and store.
      if (creds && !editing.id) {
        const listed = await api.backup.list(serverId);
        const newest = (listed.jobs as BackupJob[]).slice().sort((a, b) => (b.updated_at_ns ?? 0) - (a.updated_at_ns ?? 0))[0];
        if (newest) {
          const payload = JSON.stringify({ access_key: creds.access_key, secret_key: creds.secret_key });
          await vault.backupSet(`backup:${newest.id}`, payload);
        }
      } else if (creds && editing.id) {
        const payload = JSON.stringify({ access_key: creds.access_key, secret_key: creds.secret_key });
        await vault.backupSet(`backup:${editing.id}`, payload);
      }
      setEditing(null);
      setEditingJob(null);
      void load();
    } catch (e) {
      const be = e instanceof BridgeError ? e : null;
      setError(be ? `${be.code}: ${be.message}` : String(e));
    }
  };

  const beginEdit = (j: BackupJob) => {
    setEditingJob(j);
    const d = jobToDraft(j);
    // Try to hint that a scheduled non-IAM job needs its Keychain entry repopulated.
    d.access_key = "";
    d.secret_key = "";
    setEditing(d);
  };

  if (loading && !hasLoaded) {
    return <OarsLoadingState title="Loading backups" detail="Oars is reading backup jobs and retention settings." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)", alignItems: "center", flexWrap: "wrap" }}>
        {loading && <OarsRefreshStatus label="Updating jobs" />}
        <Button size="sm" onClick={() => { setEditing(emptyDraft()); setEditingJob(null); }}>
          <Plus /> New backup
        </Button>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          <RefreshCw /> Refresh
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              const r = await api.backup.install(serverId, "rclone", true);
              setError(`Plan: ${r.plan}`);
            } catch (e) {
              const be = e instanceof BridgeError ? e : null;
              setError(be ? `${be.code}: ${be.message}` : String(e));
            }
          }}
        >
          Install plan (rclone)
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              const r: unknown = await api.backup.cronStatus(serverId);
              setError(JSON.stringify(r));
              setTimeout(() => setError((prev) => prev === JSON.stringify(r) ? null : prev), 3000);
            } catch (e) {
              const be = e instanceof BridgeError ? e : null;
              setError(be ? `${be.code}: ${be.message}` : String(e));
            }
          }}
        >
          Cron status
        </Button>
        {activeRunId && (
          <Button size="sm" variant="outline" onClick={async () => {
            try { await api.backup.runCancel(activeRunId); setRunStatus(`Cancel requested for ${activeRunId}`); } catch (e) {
              const be = e instanceof BridgeError ? e : null;
              setError(be ? `${be.code}: ${be.message}` : String(e));
            }
          }}>Cancel</Button>
        )}
      </div>
      {error && (
        <div className="oars-form-error" role="alert" style={{ margin: "8px 12px", whiteSpace: "pre-wrap" }}>
          {error}
        </div>
      )}
      {runStatus && <div className="muted" style={{ margin: "8px 12px", fontSize: 12 }}>{runStatus}</div>}
      <div style={{ padding: 12, display: "grid", gap: 8, overflow: "auto" }}>
        {jobs.map((j) => (
          <div key={j.id} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, background: "var(--card)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <strong style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 13 }}>{j.name}</strong>
              <span className="muted" style={{ fontSize: 11 }}>{humanSchedule(j)}</span>
            </div>
            <div className="muted" style={{ fontSize: 11, fontFamily: "var(--font-geist-mono, ui-monospace, monospace)" }}>
              {j.source_path} → {destLabel(j)}
            </div>
            <div className="muted" style={{ fontSize: 11 }}>
              {j.destination.use_iam ? "IAM" : "Key auth"} · rev {String(j.revision ?? 1)} {historyCounts[j.id] !== undefined ? `· ${historyCounts[j.id]} runs` : ""}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  try {
                    // Need to resolve Keychain credentials for non-IAM jobs.
                    let creds: import("./types").BackupCredentials | undefined;
                    if (!j.destination.use_iam) {
                      const raw = await vault.backupTransientGet(`backup:${j.id}`);
                      if (raw) { try { const parsed = JSON.parse(raw) as { access_key: string; secret_key: string }; creds = parsed; } catch {} }
                      if (!creds) { setError("Missing Keychain credentials for this job (backup:<job_id>). Re-enter them in Edit."); return; }
                    }
                    // Sync requires typed confirmation (NEXT-SPEC).
                    let confirmName: string | undefined;
                    if (j.transfer === "sync") {
                      const typed = window.prompt(`Type the job name to confirm sync run (destination deletes): ${j.name}`);
                      if (typed !== j.name) { setError("Sync run confirmation failed — name did not match"); return; }
                      confirmName = typed;
                    }
                    // Use new typed runOp when available (operation_id idempotency), fallback to legacy.
                    const opId = (typeof crypto !== "undefined" && "randomUUID" in crypto) ? crypto.randomUUID() : `op-${Date.now()}-${Math.random().toString(16).slice(2)}`;
                    let runId: string;
                    try {
                      const r = await api.backup.runOp(opId, serverId, j.id, (j.revision as number) ?? 1, { credentials: creds, confirmJobName: confirmName });
                      runId = (r as { run_id: string }).run_id;
                    } catch {
                      const r = await api.backup.run(serverId, j.id, creds as unknown as import("./types").BackupCredentials);
                      runId = (r as { run_id: string }).run_id;
                    }
                    setActiveRunId(runId);
                    setRunStatus(`Run ${runId} started`);
                    let cursor = 0;
                    let t = 0;
                    const poll = async () => {
                      t++;
                      try {
                        const pr = await api.backup.poll(runId, cursor);
                        cursor = (pr as unknown as { log_cursor: number }).log_cursor ?? cursor + (((pr as unknown as { log_delta: string }).log_delta?.length) ?? 0);
                        const status = (pr as unknown as { status: BackupRunStatus }).status;
                        setRunStatus(`Run ${runId} ${status} ${(pr as unknown as { bytes_done: number }).bytes_done ?? 0}B`);
                        if (status === "running" && t < 120) setTimeout(poll, 800);
                        else { setActiveRunId(null); void loadHistory(j.id); }
                      } catch {}
                    };
                    setTimeout(poll, 600);
                  } catch (e) {
                    const be = e instanceof BridgeError ? e : null;
                    setError(be ? `${be.code}: ${be.message}${be.detail?.remote_object ? ` (${be.detail.remote_object})` : ""}` : String(e));
                  }
                }}
              >
                Run now
              </Button>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  try {
                    // Best-effort: derive creds from Keychain if present.
                    let creds: import("./types").BackupCredentials | undefined;
                    if (!j.destination.use_iam) {
                      const raw = await vault.backupTransientGet(`backup:${j.id}`);
                      if (raw) { try { creds = JSON.parse(raw) as import("./types").BackupCredentials; } catch {} }
                    }
                    const jobInput: import("./types").BackupJobInput = {
                      id: j.id,
                      server_id: j.server_id,
                      name: j.name,
                      source_path: j.source_path,
                      destination: j.destination as unknown as import("./types").BackupJobInput["destination"],
                      transfer: j.transfer,
                    };
                    const r = await api.backup.test(jobInput, creds);
                    const ok = (r as { ok: boolean }).ok;
                    setError(ok ? `Test passed: ${JSON.stringify((r as { checks: unknown }).checks)}` : JSON.stringify(r));
                  } catch (e) {
                    const be = e instanceof BridgeError ? e : null;
                    const detail = be?.detail?.remote_object ? ` leftover ${be.detail.remote_object}` : "";
                    setError(be ? `${be.code}: ${be.message}${detail}` : String(e));
                  }
                }}
              >
                Test
              </Button>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => { await loadHistory(j.id); }}
              >
                History
              </Button>
              <Button size="xs" variant="outline" onClick={() => beginEdit(j)}>
                Edit
              </Button>
              <Button
                size="xs"
                variant="destructive"
                onClick={async () => {
                  const typed = window.prompt(`Type the job name to delete: ${j.name}`);
                  if (typed !== j.name) { setError("Delete confirmation failed — name did not match"); return; }
                  try {
                    await api.backup.remove(serverId, j.id);
                    await vault.backupDelete(`backup:${j.id}`).catch(() => {});
                    void load();
                  } catch (e) {
                    const be = e instanceof BridgeError ? e : null;
                    setError(be ? `${be.code}: ${be.message}` : String(e));
                  }
                }}
              >
                Delete
              </Button>
            </div>
          </div>
        ))}
        {jobs.length === 0 && <div className="muted">No backup jobs — create one</div>}
      </div>
      {editing && (
        <BackupEditModal
          editing={editing}
          setEditing={setEditing}
          editingJob={editingJob}
          onSave={handleSave}
          onClose={() => {
            setEditing((prev) => prev ? { ...prev, access_key: "", secret_key: "" } : null);
            setEditing(null);
            setEditingJob(null);
          }}
        />
      )}
    </div>
  );

  async function loadHistory(jobId: string) {
    try {
      const r = await api.backup.history(serverId, jobId);
      setHistoryCounts((prev) => ({ ...prev, [jobId]: (r.runs ?? []).length }));
      const pretty = (r.runs ?? []).map((run) => `${run.id} ${run.status} ${run.files_done}f ${run.bytes_done}B ${run.error ? `err:${run.error}` : ""}`).join("\n");
      setError(pretty || "No history");
    } catch (e) {
      const be = e instanceof BridgeError ? e : null;
      setError(be ? `${be.code}: ${be.message}` : String(e));
    }
  }
}

function BackupEditModal({
  editing,
  setEditing,
  editingJob,
  onSave,
  onClose,
}: {
  editing: EditorDraft;
  setEditing: (val: EditorDraft) => void;
  editingJob: BackupJob | null;
  onSave: () => void;
  onClose: () => void;
}) {
  const dialogRef = useModalFocus(onClose, "#backup-name", true);
  const showRegion = editing.provider === "aws";
  const needsEndpoint = editing.provider !== "aws";
  const isR2 = editing.provider === "r2";
  const httpWarning = editing.endpoint.startsWith("http://");
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={dialogRef}
        className="oars-modal oars-modal-narrow"
        role="dialog"
        aria-modal="true"
        aria-labelledby="backup-edit-title"
        aria-describedby="backup-edit-desc"
      >
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <div>
              <h2 id="backup-edit-title">{editing.id ? "Edit backup" : "New backup"}</h2>
              <p id="backup-edit-desc" className="oars-modal-subtitle">Source, S3 destination, auth, transfer, and schedule.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body" style={{ display: "grid", gap: 12 }}>
          <div className="oars-field">
            <label htmlFor="backup-name">Name</label>
            <input id="backup-name" type="text" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="daily-website" />
          </div>
          <div className="oars-field">
            <label htmlFor="backup-source">Source path (absolute)</label>
            <input id="backup-source" type="text" value={editing.source_path} onChange={(e) => setEditing({ ...editing, source_path: e.target.value })} placeholder="/var/www" style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)" }} />
          </div>

          <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, display: "grid", gap: 10 }}>
            <strong style={{ fontSize: 12 }}>Destination</strong>
            <div className="oars-field">
              <label htmlFor="backup-provider">Provider</label>
              <OarsSelect
                id="backup-provider"
                value={editing.provider}
                onValueChange={(v) => setEditing({ ...editing, provider: v })}
                options={[
                  { value: "aws", label: "AWS S3" },
                  { value: "r2", label: "Cloudflare R2 (Cloudflare, endpoint required, region auto)" },
                  { value: "b2_s3", label: "Backblaze B2 (S3-compatible, endpoint required)" },
                  { value: "wasabi", label: "Wasabi" },
                  { value: "minio", label: "MinIO (endpoint required)" },
                  { value: "spaces", label: "DigitalOcean Spaces (endpoint required)" },
                ]}
              />
            </div>
            <div className="oars-field">
              <label htmlFor="backup-bucket">Bucket</label>
              <input id="backup-bucket" type="text" value={editing.bucket} onChange={(e) => setEditing({ ...editing, bucket: e.target.value })} />
            </div>
            <div className="oars-field">
              <label htmlFor="backup-prefix">Prefix (optional)</label>
              <input id="backup-prefix" type="text" value={editing.prefix} onChange={(e) => setEditing({ ...editing, prefix: e.target.value })} placeholder="backups/daily" />
            </div>
            <div className="oars-field">
              <label htmlFor="backup-endpoint">Endpoint {needsEndpoint ? "(required)" : "(optional)"} {isR2 ? "— R2 requires S3 endpoint" : ""}</label>
              <input id="backup-endpoint" type="text" value={editing.endpoint} onChange={(e) => setEditing({ ...editing, endpoint: e.target.value })} placeholder="https://s3.amazonaws.com" style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)" }} />
              {httpWarning && (
                <span style={{ fontSize: 11, color: "var(--destructive, #b91c1c)", display: "flex", gap: 6, alignItems: "center" }}><AlertTriangle size={12} /> Plain http is allowed only for private MinIO test endpoints. Prefer https.</span>
              )}
            </div>
            {showRegion && (
              <div className="oars-field">
                <label htmlFor="backup-region">Region {showRegion ? "(required for AWS)" : ""}</label>
                <input id="backup-region" type="text" value={editing.region} onChange={(e) => setEditing({ ...editing, region: e.target.value })} placeholder="us-east-1" />
              </div>
            )}
            {isR2 && <div className="muted" style={{ fontSize: 11 }}>R2 region is fixed to auto</div>}
            <div className="oars-field">
              <label htmlFor="backup-storage-class">Storage class</label>
              <input id="backup-storage-class" type="text" value={editing.storage_class} onChange={(e) => setEditing({ ...editing, storage_class: e.target.value })} placeholder="standard" />
              <span className="muted" style={{ fontSize: 11 }}>Only adapter allow-listed classes are valid; empty/default omitted from rclone config.</span>
            </div>
            <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
              <input type="checkbox" checked={editing.use_iam} onChange={(e) => setEditing({ ...editing, use_iam: e.target.checked })} />
              Use AWS runtime/IAM (no keys stored; rclone env_auth=true)
            </label>
            {!editing.use_iam && (
              <>
                <div className="oars-field">
                  <label htmlFor="backup-access">Access key</label>
                  <input id="backup-access" type="password" value={editing.access_key} onChange={(e) => setEditing({ ...editing, access_key: e.target.value })} autoComplete="off" />
                </div>
                <div className="oars-field">
                  <label htmlFor="backup-secret">Secret key</label>
                  <input id="backup-secret" type="password" value={editing.secret_key} onChange={(e) => setEditing({ ...editing, secret_key: e.target.value })} autoComplete="off" />
                </div>
                {editingJob && editing.enabled && editing.schedule_mode !== "manual" && (
                  <div className="muted" style={{ fontSize: 11, border: "1px solid var(--border)", padding: 8, borderRadius: 6 }}>
                    Scheduled non-IAM jobs copy credentials to the server&apos;s rclone.conf (mode 0600). Rclone obscuring is not encryption — review before enabling.
                  </div>
                )}
              </>
            )}
          </div>

          <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, display: "grid", gap: 10 }}>
            <strong style={{ fontSize: 12 }}>Transfer</strong>
            <OarsSelect
              id="backup-transfer"
              value={editing.transfer}
              onValueChange={(v) => setEditing({ ...editing, transfer: v as EditorDraft["transfer"] })}
              options={[
                { value: "copy", label: "Copy — adds/updates, never deletes destination extras" },
                { value: "sync", label: "Sync — mirrors source, deletes destination extras (requires typed confirmation)" },
              ]}
            />
            {editing.transfer === "sync" && (
              <span style={{ fontSize: 11, color: "var(--destructive, #b91c1c)", display: "flex", gap: 6 }}><AlertTriangle size={12} /> Sync will delete files in the destination that are not in the source.</span>
            )}
          </div>

          <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, display: "grid", gap: 10 }}>
            <strong style={{ fontSize: 12 }}>Schedule</strong>
            <OarsSelect
              id="backup-schedule-mode"
              value={editing.schedule_mode}
              onValueChange={(v) => setEditing({ ...editing, schedule_mode: v as EditorDraft["schedule_mode"] })}
              options={[
                { value: "manual", label: "Manual" },
                { value: "interval", label: "Interval (hours/days — wrapper-gated)" },
                { value: "custom", label: "Custom cron (5 fields)" },
              ]}
            />
            {editing.schedule_mode === "interval" && (
              <div style={{ display: "flex", gap: 8 }}>
                <input type="number" min={1} max={365} value={editing.interval_every} onChange={(e) => setEditing({ ...editing, interval_every: Number(e.target.value) || 1 })} style={{ width: 100 }} />
                <OarsSelect
                  id="backup-interval-unit"
                  value={editing.interval_unit}
                  onValueChange={(v) => setEditing({ ...editing, interval_unit: v as EditorDraft["interval_unit"] })}
                  options={[{ value: "hours", label: "hours (1–168)" }, { value: "days", label: "days (1–365)" }]}
                />
              </div>
            )}
            {editing.schedule_mode === "custom" && (
              <div className="oars-field">
                <label htmlFor="backup-expr">Cron expression (server timezone)</label>
                <input id="backup-expr" type="text" value={editing.expr} onChange={(e) => setEditing({ ...editing, expr: e.target.value })} placeholder="0 2 * * *" style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)" }} />
                <span className="muted" style={{ fontSize: 11 }}>Custom times run in the server cron daemon&apos;s local timezone; DST can skip/repeat.</span>
              </div>
            )}
            <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
              <input type="checkbox" checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
              Enabled
            </label>
          </div>
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button onClick={onSave}>Save</Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}
