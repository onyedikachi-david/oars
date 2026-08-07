import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

interface DeployApp {
  id: string;
  server_id: string;
  name: string;
  environment: string;
  folder: string;
  repo: { url: string; transport: string; branch: string };
  runtime: { node_version: string; type: string; install: string; build: string; start: string; build_folder: string };
  env_vars: Array<{ name: string; secret: boolean; value?: string; has_value?: boolean }>;
  domains: string[];
  ssl: boolean;
  email: string;
  app_port: number;
}

interface RunStep {
  id: string;
  label: string;
  state: string;
  channel?: number;
  exit?: number | null;
  error?: string;
  output?: string;
}

export function DeployTab({ serverId }: { serverId: string }) {
  const [apps, setApps] = useState<DeployApp[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Partial<DeployApp> | null>(null);
  const [runId, setRunId] = useState<number | null>(null);
  const [runStatus, setRunStatus] = useState<string>("");
  const [steps, setSteps] = useState<RunStep[]>([]);
  const [history, setHistory] = useState<any[]>([]);

  const load = useCallback(async () => {
    try {
      const r: any = await api.deploy.list(serverId);
      setApps(r.apps ?? []);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  }, [serverId]);

  useEffect(() => { load(); }, [load]);

  const handleSave = async () => {
    if (!editing?.name?.trim() || !editing?.folder?.trim() || !editing?.repo?.url?.trim()) {
      setError("Name, folder, repo URL required");
      return;
    }
    try {
      await api.deploy.save({
        id: editing.id,
        server_id: serverId,
        name: editing.name!.trim(),
        environment: (editing.environment as string) ?? "production",
        folder: editing.folder!.trim(),
        repo: {
          url: editing.repo!.url.trim(),
          transport: editing.repo!.transport ?? "https",
          branch: editing.repo!.branch ?? "main",
        },
        runtime: {
          node_version: editing.runtime?.node_version ?? "22",
          type: editing.runtime?.type ?? "node",
          install: editing.runtime?.install ?? "",
          build: editing.runtime?.build ?? "",
          start: editing.runtime?.start ?? "",
          build_folder: editing.runtime?.build_folder ?? "",
        },
        env_vars: (editing.env_vars as any) ?? [],
        domains: editing.domains ?? [],
        ssl: !!editing.ssl,
        email: editing.email ?? "",
        app_port: editing.app_port ?? 3000,
      } as any);
      setEditing(null);
      load();
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  const handleRun = async (app: DeployApp) => {
    // collect secret values via prompt (Keychain-backed secrets stay local)
    const secretVars = (app.env_vars ?? []).filter((v) => v.secret);
    const secret_values: Array<{ name: string; value: string }> = [];
    for (const v of secretVars) {
      const val = prompt(`Secret value for ${v.name}:`, "");
      if (val === null) return;
      // empty means skip (has_value already)
      if (val) secret_values.push({ name: v.name, value: val });
    }
    try {
      const r: any = await api.deploy.run(serverId, app.id, secret_values);
      setRunId(r.run_id);
      setSteps([]);
      setRunStatus("running");
      // load history soon
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  // poll deploy run
  useEffect(() => {
    if (runId == null) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const r: any = await api.deploy.poll(runId);
        if (cancelled) return;
        setRunStatus(r.status);
        setSteps(r.steps ?? []);
        if (r.status === "running" || r.status === "pending") setTimeout(poll, 800);
        else {
          // refresh history
          const appId = apps.find(() => true)?.id;
          if (appId) {
            try {
              const h: any = await api.deploy.history(serverId, appId);
              setHistory(h.runs ?? []);
            } catch {}
          }
        }
      } catch {}
    };
    poll();
    return () => { cancelled = true; };
  }, [runId, serverId, apps]);

  const loadHistory = async (appId: string) => {
    try {
      const r: any = await api.deploy.history(serverId, appId);
      setHistory(r.runs ?? []);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  return (
    <div className="deploy">
      <div className="deploy-toolbar" style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)" }}>
        <button className="btn" onClick={() => setEditing({ name: "", folder: `/home/ubuntu/app`, repo: { url: "", transport: "https", branch: "main" }, runtime: { node_version: "22", type: "next", install: "npm ci", build: "npm run build", start: "npm start", build_folder: "" }, domains: [], ssl: false, app_port: 3000 })}>
          + New app
        </button>
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      {error && <div className="form-error" style={{ margin: "8px 12px" }}>{error}</div>}
      <div style={{ padding: 12, display: "grid", gap: 12 }}>
        {apps.map((a) => (
          <div key={a.id} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--bg-elevated)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <strong>{a.name}</strong>
              <span className="muted" style={{ fontSize: 11 }}>{a.environment} · {a.folder} · {a.repo.branch}</span>
            </div>
            <div className="muted" style={{ fontSize: 11 }}>{a.repo.transport}: {a.repo.url}</div>
            <div className="muted" style={{ fontSize: 11 }}>{a.runtime.type} · node {a.runtime.node_version} · port {a.app_port}</div>
            <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
              <button className="btn" onClick={() => handleRun(a)}>Deploy</button>
              <button className="btn" onClick={() => setEditing(a as any)}>Edit</button>
              <button className="btn" onClick={() => loadHistory(a.id)}>History</button>
              <button className="btn" onClick={async () => { if (!confirm(`Delete ${a.name}?`)) return; await api.deploy.remove(serverId, a.id); load(); }}>Delete</button>
            </div>
          </div>
        ))}
        {apps.length === 0 && <div className="muted">No apps yet — create one to deploy</div>}
      </div>

      {runId != null && (
        <div style={{ borderTop: "1px solid var(--border)", padding: 12, background: "var(--bg-elevated)" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Run #{runId} · {runStatus}</div>
          <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
            {steps.map((s) => (
              <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, padding: "6px 8px", border: "1px solid var(--border)", borderRadius: 6, background: s.state === "failed" ? "rgba(220,60,60,0.12)" : s.state === "success" ? "rgba(40,160,80,0.12)" : "var(--bg)" }}>
                <span style={{ width: 8, height: 8, borderRadius: 999, background: s.state === "success" ? "#2a8" : s.state === "failed" ? "#c33" : s.state === "running" ? "#eab308" : "#888" }} />
                <strong>{s.label}</strong>
                <span className="muted">{s.state}</span>
                {s.error && <span style={{ color: "#c33" }}>{s.error}</span>}
                {s.exit != null && <span className="muted">exit {s.exit}</span>}
              </div>
            ))}
          </div>
          {steps.map((s) => s.output ? <pre key={s.id} className="log-lines" style={{ maxHeight: 140, marginTop: 8 }}>{s.output}</pre> : null)}
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button className="btn" onClick={async () => { if (runId != null) await api.deploy.cancel(runId); }}>Cancel</button>
            <button className="btn" onClick={() => setRunId(null)}>Close</button>
          </div>
        </div>
      )}

      {history.length > 0 && (
        <div style={{ borderTop: "1px solid var(--border)", padding: 12 }}>
          <div style={{ fontWeight: 600, fontSize: 12 }}>Recent runs</div>
          <div className="muted" style={{ fontSize: 11 }}>{history.length} runs</div>
          {history.map((h: any, i: number) => (
            <div key={i} className="muted" style={{ fontSize: 11, borderBottom: "1px solid var(--border)", padding: "4px 0" }}>
              {h.status ?? h.state} · {new Date((h.started_at ?? h.ts ?? 0) / 1e6).toLocaleString()} · {h.app_id ?? ""}
            </div>
          ))}
        </div>
      )}

      {editing && (
        <div className="overlay" onClick={() => setEditing(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()} style={{ width: 680, maxHeight: "85vh", overflow: "auto" }}>
            <div className="dialog-header">{editing.id ? "Edit app" : "New app"}</div>
            <div className="dialog-body">
              <div className="form">
                <div className="row"><label>Name</label><input type="text" value={(editing.name as string) ?? ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></div>
                <div className="row"><label>Folder (abs)</label><input type="text" value={(editing.folder as string) ?? ""} onChange={(e) => setEditing({ ...editing, folder: e.target.value })} placeholder="/home/ubuntu/myapp" /></div>
                <div className="row"><label>Repo URL</label><input type="text" value={(editing.repo as any)?.url ?? ""} onChange={(e) => setEditing({ ...editing, repo: { ...(editing.repo as any), url: e.target.value } })} placeholder="https://github.com/you/app.git" /></div>
                <div className="row"><label>Transport</label>
                  <select value={(editing.repo as any)?.transport ?? "https"} onChange={(e) => setEditing({ ...editing, repo: { ...(editing.repo as any), transport: e.target.value } })}>
                    <option value="https">https</option><option value="ssh">ssh</option><option value="file">file</option>
                  </select>
                </div>
                <div className="row"><label>Branch</label><input type="text" value={(editing.repo as any)?.branch ?? "main"} onChange={(e) => setEditing({ ...editing, repo: { ...(editing.repo as any), branch: e.target.value } })} /></div>
                <div className="row"><label>Node</label>
                  <select value={(editing.runtime as any)?.node_version ?? "22"} onChange={(e) => setEditing({ ...editing, runtime: { ...(editing.runtime as any), node_version: e.target.value } })}>
                    <option value="22">22</option><option value="24">24</option>
                  </select>
                </div>
                <div className="row"><label>App type</label>
                  <select value={(editing.runtime as any)?.type ?? "node"} onChange={(e) => setEditing({ ...editing, runtime: { ...(editing.runtime as any), type: e.target.value } })}>
                    <option value="node">node</option><option value="react">react</option><option value="next">next</option><option value="static">static</option>
                  </select>
                </div>
                <div className="row"><label>Install</label><input type="text" value={(editing.runtime as any)?.install ?? ""} onChange={(e) => setEditing({ ...editing, runtime: { ...(editing.runtime as any), install: e.target.value } })} /></div>
                <div className="row"><label>Build</label><input type="text" value={(editing.runtime as any)?.build ?? ""} onChange={(e) => setEditing({ ...editing, runtime: { ...(editing.runtime as any), build: e.target.value } })} /></div>
                <div className="row"><label>Start</label><input type="text" value={(editing.runtime as any)?.start ?? ""} onChange={(e) => setEditing({ ...editing, runtime: { ...(editing.runtime as any), start: e.target.value } })} /></div>
                <div className="row"><label>Env vars (NAME=val or secret)</label>
                  <textarea rows={3} value={((editing.env_vars as any[]) ?? []).map((v: any) => `${v.name}=${v.secret ? "(secret)" : v.value ?? ""}`).join("\n")} onChange={(e) => {
                    const lines = e.target.value.split("\n").map((s) => s.trim()).filter(Boolean);
                    const vars = lines.map((line) => {
                      const eq = line.indexOf("=");
                      const name = eq >= 0 ? line.slice(0, eq).trim() : line.trim();
                      const val = eq >= 0 ? line.slice(eq + 1).trim() : "";
                      const secret = val === "(secret)" || val === "";
                      return secret ? { name, secret: true, has_value: val === "(secret)" } : { name, secret: false, value: val };
                    });
                    setEditing({ ...editing, env_vars: vars as any });
                  }} style={{ fontFamily: "var(--mono)", fontSize: 12 }} />
                </div>
                <div className="row"><label>Domains (comma)</label><input type="text" value={(editing.domains as any ?? []).join(", ")} onChange={(e) => setEditing({ ...editing, domains: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) as any })} /></div>
                <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
                  <button className="btn" onClick={() => setEditing(null)}>Cancel</button>
                  <button className="btn" onClick={handleSave}>Save</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
