import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../bridge";
import type { Server, SessionStatus } from "../types";
import { fleetRollup } from "../fleet";
import { Button } from "./ui/button";
import { GroupEditDialog } from "./GroupEditDialog";

import { ResourceChart } from "./LazyResourceChart";
import { ConnectionStatus } from "./ConnectionStatus";
import { appendResourceSample, type ResourceSample } from "../resource-history";
import { snapshotMilliseconds } from "../monitor-state";
import { ArrowLeft, ArrowUpRight, RefreshCw, Server as ServerIcon } from "lucide-react";

function GroupCard({ server, status, refresh, onStatus, onOpen }: { server: Server; status?: SessionStatus; refresh: number; onStatus: (id: string, status: SessionStatus) => void; onOpen: (server: Server) => void }) {
  const ref = useRef<HTMLDivElement>(null); const [visible, setVisible] = useState(typeof IntersectionObserver === "undefined"); const [history, setHistory] = useState<ResourceSample[]>([]); const [error, setError] = useState(""); const [updated, setUpdated] = useState<number | null>(null);
  useEffect(() => {
    if (!ref.current || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting)); observer.observe(ref.current); return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (!visible) return;
    let disposed = false; let timer: ReturnType<typeof setTimeout>; let lastTimestamp: number | null = null;
    async function poll() {
      try {
        const state = await api.ssh.status(server.id);
        if (disposed) return;
        onStatus(server.id, state.status);
        if (state.status === "ready") {
          const snapshot = await api.monitor.poll(server.id);
          if (disposed) return;
          setError(snapshot.probe_error ?? ""); setUpdated(snapshotMilliseconds(snapshot.ts) || null);
          if (snapshot.ts !== lastTimestamp) { lastTimestamp = snapshot.ts; setHistory(previous => appendResourceSample(previous, snapshot, 60)); }
        } else { setError(state.error ?? ""); setUpdated(null); }
      } catch (e) { if (!disposed) { setError(e instanceof Error ? e.message : String(e)); setUpdated(null); } }
      if (!disposed) timer = setTimeout(poll, 5000);
    }
    void poll(); return () => { disposed = true; clearTimeout(timer); };
  }, [visible, server.id, onStatus, refresh]);
  return <div ref={ref} className="fleet-resource-card">
    <header><div><h3><ServerIcon size={15} aria-hidden />{server.name}</h3><span className="fleet-resource-host">{server.host}:{server.port}</span></div><ConnectionStatus status={status} label /></header>
    {updated !== null ? <ResourceChart samples={history} compact /> : <div className="fleet-resource-offline"><ConnectionStatus status={status} /><strong>{error ? "Metrics unavailable" : "No live connection"}</strong><p>{error || "Open this server to connect and read resource use."}</p></div>}
    <footer><span>{updated === null ? "No current sample" : `Sampled ${new Date(updated).toLocaleTimeString()}`}</span><Button variant="ghost" size="sm" aria-label={`Open ${server.name}`} onClick={() => onOpen(server)}>Open server <ArrowUpRight /></Button></footer>
    {updated !== null && error && <p role="alert">{error}</p>}
  </div>;
}
export function GroupView({ group, servers, statuses, onStatus, onOpen, onOpenAll, onRunScript, onUpdated, onBack }: { group: string; servers: Server[]; statuses: ReadonlyMap<string, SessionStatus>; onStatus: (id: string, status: SessionStatus) => void; onOpen: (server: Server) => void; onOpenAll: () => void; onRunScript: () => void; onUpdated: (servers: Server[]) => void; onBack: () => void }) {
  const [page, setPage] = useState(0); const [refresh, setRefresh] = useState(0); const [edit, setEdit] = useState<"rename" | "delete" | null>(null); const [scanBusy, setScanBusy] = useState(false); const [scanResults, setScanResults] = useState<Array<{ name: string; summary: string }>>([]);
  const rollup = fleetRollup(servers, statuses); const maxPage = Math.max(0, Math.ceil(servers.length / 12) - 1); const effectivePage = Math.min(page, maxPage);
  const scan = useCallback(async () => {
    setScanBusy(true); setScanResults([]);
    for (const server of servers) {
      let summary: string;
      try { const result = await api.logs.scan(server.id); summary = `${result.sources.length} log sources${result.partial ? ` · partial: ${result.reason}` : ""}`; }
      catch (e) { summary = e instanceof Error ? e.message : String(e); }
      setScanResults(previous => [...previous, { name: server.name, summary }]);
    }
    setScanBusy(false);
  }, [servers]);
  return <div className="oars-data-view fleet-group-view">
    <section className="fleet-group-heading"><Button size="sm" variant="ghost" onClick={onBack}><ArrowLeft /> Back to servers</Button><h2>{group || "Ungrouped"}</h2><p role="status">{rollup.total} profiles · {rollup.connected} connected · {rollup.errors} errors</p>
      <div className="oars-data-actions"><Button size="sm" onClick={onOpenAll}>Open all</Button><Button size="sm" variant="outline" onClick={onRunScript}>Run script…</Button><Button size="sm" variant="outline" disabled={scanBusy} onClick={() => void scan()}>Scan logs</Button><Button size="sm" variant="outline" onClick={() => setRefresh(value => value + 1)}><RefreshCw /> Refresh</Button>{group && <><Button size="sm" variant="ghost" onClick={() => setEdit("rename")}>Rename group…</Button><Button size="sm" variant="ghost" onClick={() => setEdit("delete")}>Delete group…</Button></>}</div>
    </section>
    <div className="oars-fleet-grid">{servers.slice(effectivePage * 12, effectivePage * 12 + 12).map(server => <GroupCard key={server.id} server={server} status={statuses.get(server.id)} refresh={refresh} onStatus={onStatus} onOpen={onOpen} />)}</div>
    {servers.length > 12 && <div className="oars-data-actions"><Button disabled={effectivePage === 0} onClick={() => setPage(effectivePage - 1)}>Previous</Button><span>Page {effectivePage + 1} of {maxPage + 1}</span><Button disabled={effectivePage >= maxPage} onClick={() => setPage(effectivePage + 1)}>Next</Button></div>}
    <p className="muted">Visible cards refresh every 5 seconds. Up to 12 cards are monitored at once.</p>
    {(scanBusy || scanResults.length > 0) && <section className="oars-data-section"><h2>Log scan</h2><div role="status">{scanBusy ? "Scanning group…" : "Scan finished"}</div>{scanResults.map(result => <p key={result.name}>{result.name}: {result.summary}</p>)}</section>}
    {edit && <GroupEditDialog servers={servers} group={group} remove={edit === "delete"} onUpdated={onUpdated} onClose={() => setEdit(null)} />}
  </div>;
}
