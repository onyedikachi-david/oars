import { useEffect, useId, useState } from "react";
import { Terminal, ShieldCheck, ArrowRight } from "lucide-react";
import { api } from "../bridge";
import { serverGroupDraft } from "../fleet";
import type { HistoryShell, Server } from "../types";
import { ApprovalDialog } from "../features/files/dialogs/ApprovalDialog";
import { Button } from "./ui/button";
import { OarsSelect } from "./ui/select";
import { ExecOutput } from "./ExecOutput";

export function ShellIntegrationDialog({ server, connected, onUpdated, onClose }: { server: Server; connected: boolean; onUpdated: (server: Server) => void; onClose: () => void }) {
  const id = useId(); const [shell, setShell] = useState<Exclude<HistoryShell, "off">>(server.history_shell && server.history_shell !== "off" ? server.history_shell : "bash");
  const [plan, setPlan] = useState<Awaited<ReturnType<typeof api.history.shellPreview>> | null>(null); const [error, setError] = useState(""); const [status, setStatus] = useState(""); const [busy, setBusy] = useState(false); const [job, setJob] = useState<{ channel: number; connection_id: number } | null>(null);
  useEffect(() => {
    if (!connected) return;
    let active = true; setPlan(null); setError("");
    api.history.shellPreview(server.id, shell).then(result => { if (active) setPlan(result); }).catch(e => { if (active) setError(e instanceof Error ? e.message : String(e)); });
    return () => { active = false; };
  }, [server.id, shell, connected]);
  const saveMode = async (mode: HistoryShell) => {
    const latest = (await api.servers.list()).servers.find(item => item.id === server.id);
    if (!latest || latest.host !== server.host || latest.port !== server.port || latest.user !== server.user) throw new Error("The connection profile changed. Close this dialog and review it again.");
    const updated = (await api.servers.save({ ...serverGroupDraft(latest, latest.group), history_shell: mode })).server;
    onUpdated(updated);
  };
  return <ApprovalDialog className="shell-setup-dialog" quietOverlay icon={<Terminal />} iconClass="" title="Shell command history" labelledBy={`${id}-title`} subtitle={`${server.name} (${server.user}@${server.host}:${server.port})`} busy={busy} onCancel={() => { if (!busy) onClose(); }} actions={<>
    <Button variant="ghost" disabled={busy} onClick={onClose}>Close</Button>
    {server.history_shell && server.history_shell !== "off" && <Button variant="outline" disabled={busy} onClick={async () => {
      setBusy(true); setError("");
      try { await saveMode("off"); await api.history.shellDisable(server.id); setStatus("Shell history disabled for this session and future connections. Existing history is kept."); }
      catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      finally { setBusy(false); }
    }}>Disable shell history</Button>}
    <Button disabled={busy || !plan || !connected} onClick={async () => {
      if (!plan) return; setBusy(true); setError(""); setStatus("");
      try { setJob(await api.history.shellInstall(server.id, shell, plan.sha256, plan.connection_id)); }
      catch (e) { setError(e instanceof Error ? e.message : String(e)); setBusy(false); }
    }}>Install integration <ArrowRight size={14} /></Button>
  </>}>
    <div className="shell-setup-intro"><h3>Keep shell commands in History</h3><p>Save commands, exit codes, and two output lines in the local journal.</p></div>
    <div className="shell-setup-selector"><label htmlFor={`${id}-shell`}>Shell to configure</label><OarsSelect id={`${id}-shell`} disabled={busy} value={shell} onValueChange={value => setShell(value as typeof shell)} options={[{ value: "bash", label: "Bash" }, { value: "zsh", label: "Zsh" }, { value: "fish", label: "Fish" }]} /></div>
    <div className="shell-setup-scope"><ShieldCheck size={16} aria-hidden /><p>Capture starts after reconnecting in Oars. Commands and output can contain secrets Oars cannot detect.</p></div>
    <details className="shell-setup-details"><summary>What changes on the server?</summary><p>Installs helpers in <code>~/.config/oars/shell/v1</code> and adds one guarded line to the selected shell's startup file. The hooks stay inactive in ordinary SSH sessions.</p>{shell === "bash" && <p>Bash keeps HISTCONTROL and HISTIGNORE rules. If privacy settings or another DEBUG hook prevent capture, Oars records app commands only.</p>}</details>
    {!connected && <p className="shell-setup-notice">Connect the server before previewing setup.</p>}
    {connected && !plan && !error && <p className="shell-setup-notice" role="status">Preparing setup command…</p>}
    {plan && <details className="shell-setup-details"><summary>Review remote setup command</summary><pre className="oars-data-path">{plan.command}</pre></details>}
    {job && <ExecOutput key={`${job.connection_id}:${job.channel}`} serverId={server.id} channel={job.channel} connectionId={job.connection_id} onClose={() => { if (!busy) setJob(null); }} onComplete={exit => {
      if (exit !== 0) { setError("Setup did not confirm success. Shell history was not enabled."); setBusy(false); return; }
      void saveMode(shell).then(() => setStatus("Installed and enabled for the next connection. Disconnect and reconnect this server, then check for “History: full (shell-reported)”.")).catch(e => setError(String(e))).finally(() => setBusy(false));
    }} />}
    <div role="status">{status}</div>{error && <p role="alert">{error}</p>}
  </ApprovalDialog>;
}
