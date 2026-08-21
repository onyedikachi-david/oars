import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import { AlertTriangle, Plus, RefreshCw, X } from "lucide-react";

export function BackupsTab({ serverId }: { serverId: string }) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<any | null>(null);
  const [runStatus, setRunStatus] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r: any = await api.backup.list(serverId);
      setJobs(r.jobs ?? r.backups ?? []);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setHasLoaded(true);
      setLoading(false);
    }
  }, [serverId]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleSave = async () => {
    if (!editing?.name || !editing?.paths) {
      setError("Name and paths required");
      return;
    }
    try {
      const paths =
        typeof editing.paths === "string"
          ? editing.paths.split(",").map((s: string) => s.trim()).filter(Boolean)
          : editing.paths ?? [];
      const job: import("./types").BackupJobInput = {
        id: editing.id,
        server_id: serverId,
        name: editing.name,
        source_path: paths[0] || "/var/www",
        destination: editing.s3 ? { type: "s3", provider: "aws", bucket: editing.s3.bucket } : { type: "local" },
        schedule: { mode: "interval", interval_unit: "days", interval_every: Number(editing.retention_days ?? 7), enabled: true },
      };
      await api.backup.save(job);
      setEditing(null);
      void load();
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  if (loading && !hasLoaded) {
    return <OarsLoadingState title="Loading backups" detail="Oars is reading backup jobs and retention settings." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)", alignItems: "center" }}>
        {loading && <OarsRefreshStatus label="Updating jobs" />}
        <Button size="sm" onClick={() => setEditing({ name: "", paths: "/var/www", schedule: "daily", retention_days: 7 })}>
          <Plus /> New backup
        </Button>
        <Button size="sm" variant="outline" onClick={load}>
          <RefreshCw /> Refresh
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              const r: any = await api.backup.install(serverId);
              setError(r.ok ? "Install issued" : "install failed");
            } catch (e) {
              setError(e instanceof BridgeError ? e.message : String(e));
            }
          }}
        >
          Install agent
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              const r: any = await api.backup.cronStatus(serverId);
              setError(JSON.stringify(r));
              setTimeout(() => setError(null), 3000);
            } catch (e) {
              setError(e instanceof BridgeError ? e.message : String(e));
            }
          }}
        >
          Cron status
        </Button>
      </div>
      {error && (
        <div className="oars-form-error" role="alert" style={{ margin: "8px 12px" }}>
          {error}
        </div>
      )}
      {runStatus && <div className="muted" style={{ margin: "8px 12px", fontSize: 12 }}>{runStatus}</div>}
      <div style={{ padding: 12, display: "grid", gap: 8, overflow: "auto" }}>
        {jobs.map((j: any) => (
          <div key={j.id} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, background: "var(--card)" }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <strong>{j.name}</strong>
              <span className="muted" style={{ fontSize: 11 }}>{j.schedule} · keep {j.retention_days}d</span>
            </div>
            <div className="muted" style={{ fontSize: 11, fontFamily: "var(--font-geist-mono, ui-monospace, monospace)" }}>
              {(j.paths ?? []).join(", ")}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  try {
                    const r: any = await api.backup.run(serverId, j.id);
                    const runId = r.run_id ?? r.id;
                    setRunStatus(`Run #${runId} started`);
                    let t = 0;
                    const poll = async () => {
                      t++;
                      try {
                        const pr: any = await api.backup.poll(runId);
                        setRunStatus(`Run #${runId} ${pr.status ?? pr.state}`);
                        if ((pr.status === "running" || pr.state === "running") && t < 60) setTimeout(poll, 800);
                      } catch {}
                    };
                    setTimeout(poll, 600);
                  } catch (e) {
                    setError(e instanceof BridgeError ? e.message : String(e));
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
                    const r: any = await api.backup.test(serverId, j.id);
                    setError(r.ok ? "Test ok" : JSON.stringify(r));
                  } catch (e) {
                    setError(e instanceof BridgeError ? e.message : String(e));
                  }
                }}
              >
                Test
              </Button>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  try {
                    const r: any = await api.backup.history(serverId, j.id);
                    setError(`${(r.runs ?? []).length} history runs`);
                  } catch (e) {
                    setError(e instanceof BridgeError ? e.message : String(e));
                  }
                }}
              >
                History
              </Button>
              <Button size="xs" variant="outline" onClick={() => setEditing({ ...j, paths: (j.paths ?? []).join(", ") })}>
                Edit
              </Button>
              <Button
                size="xs"
                variant="destructive"
                onClick={async () => {
                  if (!confirm(`Delete ${j.name}?`)) return;
                  try {
                    await api.backup.remove(serverId, j.id);
                    void load();
                  } catch (e) {
                    setError(e instanceof BridgeError ? e.message : String(e));
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
          onSave={handleSave}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

function BackupEditModal({
  editing,
  setEditing,
  onSave,
  onClose,
}: {
  editing: any;
  setEditing: (val: any) => void;
  onSave: () => void;
  onClose: () => void;
}) {
  const dialogRef = useModalFocus(onClose, "#backup-name", true);
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
              <p id="backup-edit-desc" className="oars-modal-subtitle">Configure backup paths and schedule.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body">
          <div className="oars-field">
            <label htmlFor="backup-name">Name</label>
            <input id="backup-name" type="text" value={editing.name ?? ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
          </div>
          <div className="oars-field">
            <label htmlFor="backup-paths">Paths (comma separated)</label>
            <input id="backup-paths" type="text" value={typeof editing.paths === "string" ? editing.paths : (editing.paths ?? []).join(", ")} onChange={(e) => setEditing({ ...editing, paths: e.target.value })} />
          </div>
          <div className="oars-field">
            <label htmlFor="backup-schedule">Schedule</label>
            <OarsSelect
              id="backup-schedule"
              value={editing.schedule ?? "daily"}
              onValueChange={(schedule) => setEditing({ ...editing, schedule })}
              options={[
                { value: "hourly", label: "Hourly" },
                { value: "daily", label: "Daily" },
                { value: "weekly", label: "Weekly" },
              ]}
            />
          </div>
          <div className="oars-field">
            <label htmlFor="backup-retention">Retention (days)</label>
            <input id="backup-retention" type="number" value={editing.retention_days ?? 7} onChange={(e) => setEditing({ ...editing, retention_days: e.target.value })} />
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
