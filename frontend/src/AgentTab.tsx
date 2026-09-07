import { useCallback, useEffect, useId, useState } from "react";
import { api } from "./bridge";
import type { AgentIdentity, PollResult, Server } from "./types";
import { Button } from "./components/ui/button";
import { ApprovalDialog } from "./features/files/dialogs/ApprovalDialog";
import { KeyRound, Copy, Check, RefreshCw, ShieldCheck, CircleOff } from "lucide-react";

export function AgentTab({ server }: { server: Server }) {
  const id = useId();
  const [copied, setCopied] = useState<string | null>(null);
  const [identities, setIdentities] = useState<AgentIdentity[]>([]);
  const [hint, setHint] = useState("");
  const [error, setError] = useState("");
  const [session, setSession] = useState<PollResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<boolean | null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [agent, state] = await Promise.all([api.agent.list(), api.ssh.status(server.id)]);
      setIdentities(agent.identities); setHint(agent.error ?? ""); setSession(state);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); setSession(null); }
    finally { setLoading(false); }
  }, [server.id]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (busy || loading) return;
    let active = true; let pending = false;
    const timer = setInterval(async () => {
      if (pending) return; pending = true;
      try { const state = await api.ssh.status(server.id); if (active) setSession(state); }
      catch { if (active) setSession(null); }
      finally { pending = false; }
    }, 2000);
    return () => { active = false; clearInterval(timer); };
  }, [server.id, busy, loading]);
  const close = () => { if (!busy) setConfirmation(null); };
  return <div className="oars-data-view agent-view">
    <header className="agent-heading"><div><h2>SSH agent</h2><p>Local keys available for server authentication.</p></div><Button size="sm" variant="outline" disabled={loading || busy} onClick={() => void load()}><RefreshCw size={14} /> Refresh</Button></header>
    <section className="agent-identities"><header><h3>Available identities</h3><span>{loading ? "Checking…" : `${identities.length} keys`}</span></header>
      {identities.map(identity => <div className="agent-identity" key={identity.fingerprint_sha256}><KeyRound size={16} aria-hidden /><div><strong>{identity.comment || identity.kind}</strong><span>{identity.kind}</span><code title={identity.fingerprint_sha256}>{identity.fingerprint_sha256}</code></div><Button size="icon-sm" variant="ghost" aria-label={`Copy fingerprint for ${identity.comment || identity.kind}`} title={copied === identity.fingerprint_sha256 ? "Copied" : "Copy fingerprint"} onClick={async () => { try { await navigator.clipboard.writeText(identity.fingerprint_sha256); setCopied(identity.fingerprint_sha256); } catch { setError("Could not copy the fingerprint. Select it and copy manually."); } }}>{copied === identity.fingerprint_sha256 ? <Check /> : <Copy />}</Button></div>)}
      {!loading && !identities.length && <div className="agent-empty"><KeyRound size={20} aria-hidden /><h4>No agent identities available</h4><p>Start your SSH agent and add a key with <code>ssh-add</code>.</p></div>}
      {hint && <p role="status">{hint}</p>}
      <p className="agent-footnote">Manage these keys with your operating system's agent tools.</p>
    </section>
    <section className="agent-forwarding"><header><div><h3>Agent forwarding</h3><p>{server.name} · {server.host}</p></div><span className="agent-forwarding-state" role="status">{session?.status !== "ready" ? <><CircleOff size={14} />Disconnected</> : session.forwarding ? <><ShieldCheck size={14} />Enabled</> : <><CircleOff size={14} />Disabled</>}</span></header>
      <p>Forwarding lets this server authenticate with your local keys. Enable it only for a server you trust.</p>
      <footer><span>{session?.status === "ready" ? "Changing this restarts every mirrored shell and can interrupt running work." : "Connect this server to change forwarding."}</span><Button size="sm" variant="outline" disabled={busy || loading || session?.status !== "ready"} onClick={() => setConfirmation(!session?.forwarding)}>{session?.forwarding ? "Disable forwarding…" : "Enable forwarding…"}</Button></footer>
    </section>
    {copied && <span className="sr-only" role="status">Fingerprint copied.</span>}
    {loading && <div role="status">Checking agent and session…</div>}
    {error && <div className="oars-form-error" role="alert">{error}</div>}
    {confirmation !== null && <ApprovalDialog icon={<KeyRound />} iconClass="" labelledBy={`${id}-forward`} title={confirmation ? "Enable agent forwarding?" : "Disable agent forwarding?"} subtitle={`${server.name} (${server.user}@${server.host}:${server.port}) — this restarts the current shell.`} onCancel={close} busy={busy} actions={<>
      <Button variant="ghost" disabled={busy} onClick={close}>Cancel</Button>
      <Button disabled={busy} onClick={async () => {
        setBusy(true); setError("");
        try { await api.agent.forward(server.id, confirmation); setConfirmation(null); }
        catch (e) { setError(e instanceof Error ? e.message : String(e)); setConfirmation(null); }
        finally {
          try { setSession(await api.ssh.status(server.id)); } catch { setSession(null); }
          setBusy(false);
        }
      }}>Restart shell and {confirmation ? "enable" : "disable"}</Button>
    </>}><p>Any shell work in progress can be interrupted. {confirmation && "This server will be able to use your local agent until forwarding is disabled or the connection closes."}</p></ApprovalDialog>}
  </div>;
}
