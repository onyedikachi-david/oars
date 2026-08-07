import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

interface Entry {
  name: { utf8?: string; base64?: string };
  display: string;
  kind: string;
  size: number;
  mtime: number;
  mode: string;
  uid: number;
  gid: number;
  link_target: string | null;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtTime(epoch: number): string {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function FilesTab({ serverId }: { serverId: string }) {
  const [path, setPath] = useState("/");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [newFolder, setNewFolder] = useState("");
  const [showHidden, setShowHidden] = useState(false);

  const load = useCallback(async (p: string) => {
    setLoading(true);
    setError(null);
    try {
      const r = await api.sftp.ls(serverId, p);
      setEntries(r.entries);
      setPath(p);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [serverId]);

  useEffect(() => { load("/"); }, [load]);

  const crumbs = path.split("/").filter(Boolean);
  const filtered = entries.filter((e) => showHidden || !e.display.startsWith("."));

  return (
    <div className="files">
      <div className="files-toolbar">
        <nav className="breadcrumbs">
          <button className="crumb" onClick={() => load("/")}>/</button>
          {crumbs.map((c, i) => {
            const p = "/" + crumbs.slice(0, i + 1).join("/");
            return (
              <span key={p} className="crumb-group">
                <span className="sep">/</span>
                <button className="crumb" onClick={() => load(p)}>{c}</button>
              </span>
            );
          })}
        </nav>
        <label className="toggle">
          <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} />
          hidden
        </label>
        <button className="btn" onClick={() => load(path)} disabled={loading}>
          Refresh
        </button>
      </div>

      <div className="files-actions">
        <input
          type="text"
          placeholder="new folder name"
          value={newFolder}
          onChange={(e) => setNewFolder(e.target.value)}
          className="input"
          style={{ width: 160 }}
        />
        <button
          className="btn"
          disabled={!newFolder.trim()}
          onClick={async () => {
            const p = path === "/" ? `/${newFolder.trim()}` : `${path}/${newFolder.trim()}`;
            try {
              await api.sftp.mkdir(serverId, p);
              setNewFolder("");
              load(path);
            } catch (e) {
              setError(e instanceof BridgeError ? e.message : String(e));
            }
          }}
        >
          New folder
        </button>
      </div>

      {error && <div className="form-error" style={{ margin: "8px 12px" }}>{error}</div>}

      <div className="table-wrap">
        <table className="proc-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Modified</th>
              <th>Perms</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {path !== "/" && (
              <tr className="fs-row" onClick={() => load(path.split("/").slice(0, -1).join("/") || "/")}>
                <td colSpan={5} style={{ color: "var(--text-secondary)", cursor: "pointer" }}>↑ ..</td>
              </tr>
            )}
            {filtered.map((e) => {
              const isDir = e.kind === "directory";
              const full = path === "/" ? `/${e.display}` : `${path}/${e.display}`;
              return (
                <tr key={e.display} className="fs-row">
                  <td style={{ cursor: isDir ? "pointer" : "default" }} onClick={() => isDir && load(full)}>
                    <span style={{ marginRight: 6 }}>{isDir ? "📁" : e.kind === "symlink" ? "🔗" : "📄"}</span>
                    {e.display}
                    {e.link_target && <span className="muted"> → {e.link_target}</span>}
                  </td>
                  <td>{isDir ? "—" : fmtSize(e.size)}</td>
                  <td>{fmtTime(e.mtime)}</td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{e.mode}</td>
                  <td>
                    <button
                      className="btn"
                      style={{ padding: "2px 6px", fontSize: 11 }}
                      onClick={async () => {
                        if (!confirm(`Delete ${e.display}?`)) return;
                        try {
                          await api.sftp.rm(serverId, full);
                          load(path);
                        } catch (err) {
                          setError(err instanceof BridgeError ? err.message : String(err));
                        }
                      }}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && !loading && (
              <tr><td colSpan={5} className="muted">Empty</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
