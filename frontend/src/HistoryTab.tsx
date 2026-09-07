import { useCallback, useEffect, useId, useState } from "react";
import { api, pickSaveFile } from "./bridge";
import type { AuditEntry, HistoryEntry, Server } from "./types";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { ApprovalDialog } from "./features/files/dialogs/ApprovalDialog";
import { ExecOutput } from "./components/ExecOutput";
import { auditTitle, journalTime } from "./journal-format";
import { History, Trash2, Search, RefreshCw, Download, CircleCheck, CircleHelp, CircleX, ShieldCheck } from "lucide-react";

function timestamp(ns: number) {
  const date = new Date(ns / 1e6);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : "Time unavailable";
}

export function HistoryTab({ serverId, reviewEntry, onReviewConsumed, initialAction, onActionConsumed }: { initialAction?: "clear-audit" | null; onActionConsumed?: () => void; serverId?: string; reviewEntry?: HistoryEntry | null; onReviewConsumed?: () => void }) {
  const id = useId();
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [target, setTarget] = useState(serverId ?? "");
  const [exitFilter, setExitFilter] = useState("all");
  const [auditType, setAuditType] = useState("");
  const [review, setReview] = useState<HistoryEntry | null>(null);
  const [clearOpen, setClearOpen] = useState<"audit" | "history" | null>(null);
  const [fullCoverage, setFullCoverage] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [execution, setExecution] = useState<{ serverId: string; channel: number; connectionId?: number; command?: string } | null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError("");
    const results = await Promise.allSettled([api.history.list({ limit: 500, q: query, server_id: target || undefined }), api.history.auditList({ limit: 500, q: query, type: auditType || undefined }), api.servers.list()]);
    const errors: string[] = [];
    if (results[0].status === "fulfilled") setEntries(results[0].value.entries); else errors.push(`History: ${String(results[0].reason)}`);
    if (results[1].status === "fulfilled") setAudit(results[1].value.entries); else errors.push(`Audit: ${String(results[1].reason)}`);
    if (results[2].status === "fulfilled") setServers(results[2].value.servers); else errors.push(`Servers: ${String(results[2].reason)}`);
    setError(errors.join(" ")); setLoading(false);
  }, [query, target, auditType]);
  useEffect(() => { const timer = setTimeout(() => void load(), 150); return () => clearTimeout(timer); }, [load]);
  useEffect(() => { let active = true; setFullCoverage(false); if (target) api.ssh.status(target).then(state => { if (active) setFullCoverage(state.history_full === true); }).catch(() => {}); return () => { active = false; }; }, [target, loading]);
  useEffect(() => { if (reviewEntry) { setReview(reviewEntry); onReviewConsumed?.(); } }, [reviewEntry, onReviewConsumed]);
  useEffect(() => { if (initialAction === "clear-audit") { setClearOpen("audit"); setConfirmation(""); onActionConsumed?.(); } }, [initialAction, onActionConsumed]);
  const needle = query.trim().toLowerCase();
  const visible = entries.filter(entry => (!target || entry.server_id === target) && (!needle || `${entry.command} ${entry.output_snippet}`.toLowerCase().includes(needle)) && (exitFilter === "all" || (exitFilter === "success" ? entry.exit === 0 : exitFilter === "failed" ? entry.exit !== null && entry.exit !== 0 : entry.exit === null)));
  const visibleAudit = audit.filter(entry => (!auditType || entry.type === auditType) && (!needle || `${entry.type} ${entry.target} ${entry.commands} ${entry.detail}`.toLowerCase().includes(needle)));
  const reviewServer = review ? servers.find(server => server.id === review.server_id) : null;
  const close = () => { if (!busy) { setReview(null); setClearOpen(null); setConfirmation(""); } };
  return <div className="oars-data-view history-view">
    <section className="history-heading">
      <div className="history-title"><div><h2>History</h2><p>Commands and changes recorded on this device.</p></div><span className="history-coverage"><ShieldCheck size={14} aria-hidden />{target && fullCoverage ? "Shell + app commands" : "App commands"}</span></div>
      <details className="history-coverage-note"><summary>What is captured?</summary><p>App commands are captured. Shell commands are captured only in sessions with verified shell integration. Redaction is best effort for secrets Oars did not supply. Redacted commands cannot be replayed here.</p></details>
      <div className="oars-data-actions"><Button size="sm" variant="outline" disabled={loading || busy} onClick={() => void load()}><RefreshCw /> Refresh</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => { setError(""); setClearOpen("audit"); setConfirmation(""); }}>Clear audit…</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => { setError(""); setClearOpen("history"); setConfirmation(""); }}>Clear history…</Button><Button size="sm" variant="outline" disabled={busy} onClick={async () => {
        setBusy(true); setError("");
        try { const path = await pickSaveFile("Export audit journal", "oars-audit.csv"); if (path) { const result = await api.history.auditExport(path); setStatus(`Exported ${result.rows} audit entries to ${path}.`); } }
        catch (e) { setError(e instanceof Error ? e.message : String(e)); }
        finally { setBusy(false); }
      }}><Download /> Export audit CSV…</Button></div>
      <fieldset className="history-filters">
        <label className="history-search" htmlFor={`${id}-query`}><Search size={15} aria-hidden /><input id={`${id}-query`} aria-label="Search history and audit" placeholder="Search commands, output or audit events…" value={query} onChange={e => setQuery(e.target.value)} /></label>
        <div><label htmlFor={`${id}-server`}>History server</label><OarsSelect id={`${id}-server`} value={target} onValueChange={setTarget} options={[{ value: "", label: "All servers" }, ...Array.from(new Set([...servers.map(server => server.id), ...entries.map(entry => entry.server_id)])).map(key => ({ value: key, label: servers.find(server => server.id === key)?.name ?? key }))]} /></div>
        <div><label htmlFor={`${id}-exit`}>Command status</label><OarsSelect id={`${id}-exit`} value={exitFilter} onValueChange={setExitFilter} options={[{ value: "all", label: "All statuses" }, { value: "success", label: "Succeeded" }, { value: "failed", label: "Failed" }, { value: "unknown", label: "Exit status unavailable" }]} /></div>
      </fieldset>
    </section>
    <div role="status">{loading ? "Loading activity…" : status}</div>
    {error && <div className="oars-form-error" role="alert">{error}</div>}
    {execution && <ExecOutput key={`${execution.serverId}:${execution.channel}`} {...execution} onClose={() => setExecution(null)} />}
    <section className="journal-section"><header><h3>Command history <span>{visible.length}</span></h3><span>Up to 500 matching entries</span></header>
      <div className="journal-columns" aria-hidden><span>Command / server</span><span>Recorded</span><span>Result</span><span>Duration</span><span /></div>
      {visible.map(entry => <article key={entry.id} className="journal-command">
        <details><summary><code title={entry.command}>{entry.command}</code><span>{servers.find(server => server.id === entry.server_id)?.name ?? entry.server_id} · {auditTitle(entry.kind)}{entry.redacted ? " · Redacted" : ""}</span></summary>
          <div className="journal-command-detail"><h4>Command</h4><pre>{entry.command}</pre><h4>Output preview</h4><pre>{entry.output_snippet || "No output was recorded."}</pre>{entry.redacted && <p>Contains redacted values. Run a new command with fresh values through its original feature.</p>}</div>
        </details>
        <time title={timestamp(entry.ts)}>{journalTime(entry.ts)}</time>
        <span className={`journal-result ${entry.exit === 0 ? "is-success" : entry.exit === null ? "" : "is-failed"}`}>{entry.exit === 0 ? <CircleCheck /> : entry.exit === null ? <CircleHelp /> : <CircleX />}{entry.exit === null ? "Unknown" : `Exit ${entry.exit}`}</span>
        <span className="journal-duration">{entry.duration_ms === null ? "—" : `${entry.duration_ms} ms`}</span>
        <Button size="xs" variant="ghost" disabled={entry.redacted || busy} title={entry.redacted ? "Redacted commands cannot be replayed" : "Review this command before running it again"} onClick={() => { setError(""); setReview(entry); }}><History /> Replay</Button>
      </article>)}
      {!visible.length && !loading && <div className="journal-empty"><History /><h4>No matching history entries.</h4><p>Run a command in Oars, or adjust the filters above.</p></div>}
    </section>
    <section className="journal-section journal-audit"><header><h3>Audit journal <span>{visibleAudit.length}</span></h3><div><label className="sr-only" htmlFor={`${id}-audit-type`}>Action type</label><OarsSelect id={`${id}-audit-type`} value={auditType} onValueChange={setAuditType} options={[{ value: "", label: "All actions" }, ...Array.from(new Set(audit.map(entry => entry.type))).sort().map(type => ({ value: type, label: auditTitle(type) }))]} /></div></header>
      {visibleAudit.map(entry => <details key={entry.id} className="journal-event"><summary><ShieldCheck size={15} aria-hidden /><strong>{auditTitle(entry.type)}</strong><span>{entry.target}</span><time>{journalTime(entry.ts)}</time><span>{entry.result}</span></summary><div><code>{entry.type}</code>{entry.commands && <pre>{entry.commands}</pre>}<p>{entry.detail}</p></div></details>)}
      {!visibleAudit.length && !loading && <p className="journal-empty">No matching audit entries.</p>}
    </section>
    {review && <ApprovalDialog icon={<History />} iconClass="" title="Review command replay" labelledBy={`${id}-review`} subtitle="Check the command and target. The server may have changed since the original run." busy={busy} onCancel={close} actions={<><Button variant="ghost" disabled={busy} onClick={close}>Cancel</Button><Button disabled={busy || review.redacted || !reviewServer} onClick={async () => {
      setBusy(true); setError("");
      try { const result = await api.history.replay(review.id); setExecution({ serverId: review.server_id, channel: result.channel, connectionId: result.connection_id, command: review.command }); setStatus("Replay started."); setReview(null); }
      catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      finally { setBusy(false); }
    }}>Run command</Button></>}>
      <p>Target: {reviewServer ? `${reviewServer.name} (${reviewServer.user}@${reviewServer.host}:${reviewServer.port})` : `${review.server_id} — profile unavailable`}</p><pre className="oars-data-path">{review.command}</pre>
      {error && <p role="alert">{error}</p>}
    </ApprovalDialog>}
    {clearOpen && <ApprovalDialog icon={<Trash2 />} iconClass="" title={clearOpen === "audit" ? "Clear audit journal" : "Clear command history"} labelledBy={`${id}-clear`} subtitle={clearOpen === "audit" ? "This permanently removes the local audit journal. Command history is kept." : "This permanently removes local command history for all servers. The audit journal is kept."} busy={busy} onCancel={close} actions={<><Button variant="ghost" disabled={busy} onClick={close}>Cancel</Button><Button disabled={busy || confirmation !== "CLEAR"} onClick={async () => {
      setBusy(true); setError("");
      try { if (clearOpen === "audit") { await api.history.auditClear(confirmation); setAudit([]); } else { await api.history.clear(confirmation); setEntries([]); } setClearOpen(null); setConfirmation(""); setStatus(clearOpen === "audit" ? "Audit journal cleared." : "Command history cleared."); }
      catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      finally { setBusy(false); }
    }}>{clearOpen === "audit" ? "Clear audit" : "Clear history"}</Button></>}><label htmlFor={`${id}-confirm`}>Type CLEAR to confirm</label><input className="oars-data-input" id={`${id}-confirm`} autoComplete="off" value={confirmation} onChange={e => setConfirmation(e.target.value)} />{error && <p role="alert">{error}</p>}</ApprovalDialog>}
  </div>;
}
