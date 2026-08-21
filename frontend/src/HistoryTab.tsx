import { useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { RefreshCw, Trash2 } from "lucide-react";

export function HistoryTab() {
  const [entries, setEntries] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const r: any = await api.history.list({});
      setEntries(r.entries ?? r.history ?? r.items ?? []);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
    try {
      const r: any = await api.history.auditList();
      setAudit(r.entries ?? r.audit ?? []);
    } catch {}
    setHasLoaded(true);
    setLoading(false);
  };

  useEffect(() => {
    void load();
  }, []);

  if (loading && !hasLoaded) {
    return <OarsLoadingState compact title="Loading activity" detail="Oars is reading command history and the local audit journal." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)", alignItems: "center" }}>
        {loading && <OarsRefreshStatus label="Updating activity" />}
        <Button size="sm" variant="outline" onClick={load}>
          <RefreshCw /> Refresh
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            if (!confirm("Clear audit log?")) return;
            try {
              await api.history.auditClear();
              void load();
            } catch (e) {
              setError(e instanceof BridgeError ? e.message : String(e));
            }
          }}
        >
          <Trash2 /> Clear audit
        </Button>
      </div>
      {error && (
        <div className="oars-form-error" role="alert" style={{ margin: "8px 12px" }}>
          {error}
        </div>
      )}
      <div style={{ padding: 12, display: "grid", gap: 16, overflow: "auto" }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Command history ({entries.length})</div>
          {entries.map((e: any, i: number) => (
            <div
              key={e.id ?? i}
              style={{
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "8px 10px",
                marginTop: 6,
                background: "var(--card)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 11 }}>
                {e.command ?? e.text ?? JSON.stringify(e).slice(0, 120)}
              </span>
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  try {
                    const r: any = await api.history.replay(e.id);
                    setError(`Replay: ${JSON.stringify(r).slice(0, 200)}`);
                  } catch (err) {
                    setError(err instanceof BridgeError ? err.message : String(err));
                  }
                }}
              >
                Replay
              </Button>
            </div>
          ))}
          {entries.length === 0 && <div className="muted" style={{ fontSize: 11 }}>No history yet</div>}
        </div>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Audit log ({audit.length})</div>
          {audit.map((a: any, i: number) => (
            <div key={i} className="muted" style={{ fontSize: 11, borderBottom: "1px solid var(--border)", padding: "4px 0" }}>
              {a.action ?? a.type} · {a.server_id ?? ""} · {a.detail?.slice(0, 120) ?? ""}
            </div>
          ))}
          {audit.length === 0 && <div className="muted" style={{ fontSize: 11 }}>No audit entries</div>}
        </div>
      </div>
    </div>
  );
}
