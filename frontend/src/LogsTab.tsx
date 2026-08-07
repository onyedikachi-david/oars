import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";
import type { LogSource } from "./types";

function ageLabel(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}

function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function LogsTab({ serverId }: { serverId: string }) {
  const [sources, setSources] = useState<LogSource[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [lineCount, setLineCount] = useState<200 | 500 | 1000 | 5000>(200);
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [manualPath, setManualPath] = useState("");

  const scan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      const r = await api.logs.scan(serverId);
      setSources(r.sources);
      if (r.sources.length > 0 && !selected) setSelected(r.sources[0].path);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }, [serverId, selected]);

  const read = useCallback(async (path: string, n: number) => {
    setError(null);
    try {
      const r = await api.logs.read(serverId, path, n);
      setLines(r.lines);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
      setLines([]);
    }
  }, [serverId]);

  useEffect(() => { scan(); }, [scan]);

  useEffect(() => {
    if (selected) read(selected, lineCount);
  }, [selected, lineCount, read]);

  const filtered = sources.filter((s) => {
    if (!search) return true;
    return s.path.toLowerCase().includes(search.toLowerCase()) || s.name.toLowerCase().includes(search.toLowerCase());
  });

  const grouped = filtered.reduce<Record<string, LogSource[]>>((acc, s) => {
    const g = s.group || "custom";
    if (!acc[g]) acc[g] = [];
    acc[g].push(s);
    return acc;
  }, {});

  const displayedLines = search && lines.length > 0
    ? lines.filter((l) => l.toLowerCase().includes(search.toLowerCase()))
    : lines;

  return (
    <div className="logs">
      <div className="logs-panel">
        <div className="logs-toolbar">
          <input
            type="text"
            placeholder="Filter sources…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input"
          />
          <button className="btn" onClick={scan} disabled={scanning}>
            {scanning ? "Scanning…" : "Scan"}
          </button>
        </div>
        <div className="log-sources">
          {Object.entries(grouped).map(([group, items]) => (
            <div key={group} className="log-group">
              <div className="log-group-title">{group}</div>
              {items.map((s) => (
                <button
                  key={s.path}
                  className={`log-source ${selected === s.path ? "active" : ""} ${!s.readable ? "unreadable" : ""}`}
                  onClick={() => setSelected(s.path)}
                  title={s.path}
                >
                  <span className="log-name">{s.name}</span>
                  <span className="log-meta">
                    {sizeLabel(s.size)} · {ageLabel(s.age_sec)} {!s.readable ? "· 🔒" : ""}
                  </span>
                </button>
              ))}
            </div>
          ))}
          {sources.length === 0 && !scanning && <div className="muted" style={{ padding: 12 }}>No sources — click Scan</div>}
        </div>
        <div className="logs-add">
          <input
            type="text"
            placeholder="/var/log/custom.log"
            value={manualPath}
            onChange={(e) => setManualPath(e.target.value)}
            className="input"
          />
          <button
            className="btn"
            onClick={async () => {
              if (!manualPath.trim()) return;
              try {
                await api.logs.addSource(serverId, manualPath.trim());
                setManualPath("");
                scan();
              } catch (e) {
                setError(e instanceof BridgeError ? e.message : String(e));
              }
            }}
          >
            Add
          </button>
        </div>
      </div>

      <div className="logs-viewer">
        <div className="logs-viewer-toolbar">
          <span className="muted" style={{ fontSize: 12 }}>{selected ?? "No source"}</span>
          <select value={lineCount} onChange={(e) => setLineCount(Number(e.target.value) as any)} className="select">
            <option value={200}>200 lines</option>
            <option value={500}>500 lines</option>
            <option value={1000}>1,000 lines</option>
            <option value={5000}>5,000 lines</option>
          </select>
          <span className="muted" style={{ fontSize: 12 }}>{displayedLines.length} lines</span>
        </div>
        {error && <div className="form-error" style={{ margin: 12 }}>{error}</div>}
        <pre className="log-lines">
          {displayedLines.map((l, i) => (
            <div key={i} className="log-line">{l}</div>
          ))}
          {displayedLines.length === 0 && !error && <span className="muted">No lines</span>}
        </pre>
      </div>
    </div>
  );
}
