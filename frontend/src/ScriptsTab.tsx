import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

interface Script {
  id: string;
  name: string;
  description: string;
  tags: string[];
  color: string;
  body: string;
  run_count: number;
  last_run_at: number | null;
  variables: Array<{ name: string; secret: boolean }>;
}

export function ScriptsTab({ serverId }: { serverId: string }) {
  const [scripts, setScripts] = useState<Script[]>([]);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Partial<Script> | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [output, setOutput] = useState<string>("");

  const load = useCallback(async () => {
    try {
      const r = await api.scripts.list();
      setScripts(r.scripts);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = scripts.filter((s) => {
    if (!q) return true;
    const hay = `${s.name} ${s.description} ${s.tags.join(" ")}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  const handleSave = async () => {
    if (!editing?.name?.trim() || !editing?.body?.trim()) {
      setError("Name and body are required");
      return;
    }
    try {
      await api.scripts.save({
        id: editing.id,
        name: editing.name!.trim(),
        description: editing.description ?? "",
        tags: editing.tags ?? [],
        color: editing.color ?? "blue",
        body: editing.body!.trim(),
      });
      setEditing(null);
      load();
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  const handleRun = async (s: Script) => {
    const vars: Record<string, { value: string; secret: boolean }> = {};
    for (const v of s.variables) {
      const val = prompt(`Value for {{${v.name}}}${v.secret ? " (secret)" : ""}:`, "");
      if (val === null) return;
      vars[v.name] = { value: val, secret: v.secret };
    }
    setRunning(s.id);
    setOutput("");
    try {
      const r = await api.scripts.run(serverId, s.id, vars);
      // Poll output via ssh.poll
      let cursor = 0;
      const poll = async () => {
        try {
          const pr = await api.ssh.poll(serverId, false);
          const ch = pr.channels.find((c: any) => c.id === r.channel);
          if (ch) {
            setOutput(ch.data ?? "");
            if (!ch.eof) setTimeout(poll, 500);
            else setRunning(null);
            cursor = ch.cursor;
          } else {
            setRunning(null);
          }
        } catch {}
      };
      poll();
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
      setRunning(null);
    }
  };

  return (
    <div className="scripts">
      <div className="scripts-toolbar">
        <input type="text" placeholder="Search scripts…" value={q} onChange={(e) => setQ(e.target.value)} className="input" style={{ flex: 1 }} />
        <button className="btn" onClick={() => setEditing({ name: "", body: "", tags: [], color: "blue" })}>+ New script</button>
      </div>
      {error && <div className="form-error" style={{ margin: "8px 12px" }}>{error}</div>}
      <div className="scripts-list">
        {filtered.map((s) => (
          <div key={s.id} className="script-card" style={{ borderLeftColor: `var(--${s.color})` }}>
            <div className="script-head">
              <span className="script-name">{s.name}</span>
              <span className="muted" style={{ fontSize: 11 }}>{s.run_count} runs{s.last_run_at ? ` · last ${new Date(s.last_run_at).toLocaleDateString()}` : " · no runs yet"}</span>
            </div>
            {s.description && <div className="muted" style={{ fontSize: 12 }}>{s.description}</div>}
            <pre className="script-body">{s.body}</pre>
            {s.tags.length > 0 && <div className="tags">{s.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>}
            <div className="script-actions">
              <button className="btn" onClick={() => handleRun(s)} disabled={running === s.id}>{running === s.id ? "Running…" : "Run"}</button>
              <button className="btn" onClick={() => setEditing(s)}>Edit</button>
              <button className="btn" onClick={async () => { if (!confirm(`Delete ${s.name}?`)) return; await api.scripts.delete(s.id); load(); }}>Delete</button>
            </div>
          </div>
        ))}
        {filtered.length === 0 && <div className="muted" style={{ padding: 16 }}>No scripts — save your first one</div>}
      </div>

      {editing && (
        <div className="overlay" onClick={() => setEditing(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()} style={{ width: 560 }}>
            <div className="dialog-header">{editing.id ? "Edit script" : "New script"}</div>
            <div className="dialog-body">
              <div className="form">
                <div className="row"><label>Name</label><input type="text" value={editing.name ?? ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></div>
                <div className="row"><label>Description</label><input type="text" value={editing.description ?? ""} onChange={(e) => setEditing({ ...editing, description: e.target.value })} /></div>
                <div className="row"><label>Body — use {`{{var}}`}</label><textarea value={editing.body ?? ""} onChange={(e) => setEditing({ ...editing, body: e.target.value })} rows={6} style={{ fontFamily: "var(--mono)", fontSize: 12 }} /></div>
                <div className="row"><label>Tags (comma)</label><input type="text" value={(editing.tags ?? []).join(", ")} onChange={(e) => setEditing({ ...editing, tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} /></div>
                <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
                  <button className="btn" onClick={() => setEditing(null)}>Cancel</button>
                  <button className="btn" onClick={handleSave}>Save</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {output && (
        <div className="scripts-output">
          <div className="muted" style={{ padding: "8px 12px", fontSize: 11 }}>Output</div>
          <pre className="log-lines" style={{ maxHeight: 200 }}>{output}</pre>
        </div>
      )}
    </div>
  );
}
