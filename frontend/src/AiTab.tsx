import { useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { RefreshCw } from "lucide-react";

export function AiTab({ serverId }: { serverId: string }) {
  const [ctx, setCtx] = useState<any>(null);
  const [provider, setProvider] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newProvider, setNewProvider] = useState("");
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const r: any = await api.ai.context(serverId);
      setCtx(r);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
    try {
      const r: any = await api.ai.providerGet();
      setProvider(r.provider ?? r);
      const hist: any = await api.ai.history(serverId);
      setHistory(hist.entries ?? hist.history ?? []);
    } catch {}
    setHasLoaded(true);
    setLoading(false);
  };

  useEffect(() => {
    void load();
  }, [serverId]);

  if (loading && !hasLoaded) {
    return <OarsLoadingState title="Preparing AI context" detail="Oars is collecting the local server context and provider settings." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)", alignItems: "center" }}>
        {loading && <OarsRefreshStatus label="Updating context" />}
        <Button size="sm" variant="outline" onClick={load}>
          <RefreshCw /> Refresh context
        </Button>
        <span className="muted" style={{ fontSize: 11 }}>
          {provider ? `provider: ${provider.name ?? provider.type ?? JSON.stringify(provider).slice(0, 40)}` : "no provider"}
        </span>
      </div>
      {error && (
        <div className="oars-form-error" role="alert" style={{ margin: "8px 12px" }}>
          {error}
        </div>
      )}
      <div style={{ padding: 12, display: "grid", gap: 12, overflow: "auto" }}>
        <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--card)" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Server context (sent to LLM)</div>
          <pre
            role="log"
            aria-live="polite"
            aria-atomic="false"
            tabIndex={0}
            aria-label="Server context"
            style={{
              fontSize: 11,
              fontFamily: "var(--font-geist-mono, ui-monospace, monospace)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 220,
              overflow: "auto",
              background: "var(--background)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: 8,
              marginTop: 8,
            }}
          >
            {ctx ? JSON.stringify(ctx, null, 2) : "No context yet — connect the server first"}
          </pre>
        </div>
        <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--card)" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Provider</div>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <input
              style={{
                flex: 1,
                background: "var(--background)",
                color: "var(--foreground)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "6px 8px",
                fontSize: 12,
              }}
              placeholder='{"type":"openai","api_key":"..."} or leave blank'
              value={newProvider}
              onChange={(e) => setNewProvider(e.target.value)}
            />
            <Button
              size="sm"
              onClick={async () => {
                try {
                  const p = newProvider.trim() ? JSON.parse(newProvider) : { type: "none" };
                  await api.ai.providerSet(p);
                  setNewProvider("");
                  void load();
                } catch (e) {
                  setError(e instanceof BridgeError ? e.message : String(e));
                }
              }}
            >
              Save
            </Button>
          </div>
        </div>
        <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--card)" }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>History ({history.length})</div>
          {history.map((h: any, i: number) => (
            <div key={i} className="muted" style={{ fontSize: 11, borderBottom: "1px solid var(--border)", padding: "6px 0" }}>
              {h.role ?? h.type}: {(h.content ?? h.text ?? JSON.stringify(h)).slice(0, 200)}
            </div>
          ))}
          {history.length === 0 && <div className="muted" style={{ fontSize: 11 }}>No history</div>}
        </div>
      </div>
    </div>
  );
}
