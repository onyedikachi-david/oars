import { useEffect, useRef, useState } from "react";
import { api } from "../bridge";
import { Button } from "./ui/button";

export function ExecOutput({ serverId, channel, connectionId, onClose, onComplete, command }: { serverId: string; channel: number; connectionId?: number; command?: string; onClose: () => void; onComplete?: (exit: number | null) => void }) {
  const completeRef = useRef(onComplete);
  completeRef.current = onComplete;
  const finishedRef = useRef(false);
  const finish = (exit: number | null) => { if (finishedRef.current) return; finishedRef.current = true; setDone(true); completeRef.current?.(exit); };
  const [output, setOutput] = useState("");
  const [state, setState] = useState("Running");
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  const [stopping, setStopping] = useState(false);
  useEffect(() => {
    let disposed = false;
    finishedRef.current = false;
    const started = Date.now();
    let seenChannel = false;
    let cursor = 0;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = await api.ssh.poll(serverId, [{ channel, cursor }]);
        if (disposed || finishedRef.current) return;
        if (connectionId !== undefined && result.connection_id !== connectionId) { setState("Connection changed"); setError("This output belongs to an earlier connection. Run a new command to continue."); finish(null); return; }
        const entry = result.channels.find(item => item.id === channel);
        if (entry) {
          seenChannel = true;
          cursor = entry.cursor;
          setOutput(previous => (previous + (entry.dropped ? "\n[Some output was lost]\n" : "") + entry.data).slice(-262144));
          if (entry.eof && !entry.pending) { setState(entry.exit === null ? "Finished; exit status unavailable" : `Finished with exit code ${entry.exit}`); finish(entry.exit); return; }
        }
        if (result.status === "closed" || result.status === "error") { setState("Connection closed"); setError(result.error || "Connection closed before completion was confirmed."); finish(null); return; }
        if (!entry && (seenChannel || Date.now() - started > 30000)) { setState("Output unavailable"); setError("The command channel is no longer available."); finish(null); return; }
        timer = setTimeout(poll, 250);
      } catch (e) { if (!disposed) { setState("Output unavailable"); setError(e instanceof Error ? e.message : String(e)); finish(null); } }
    };
    void poll();
    return () => { disposed = true; clearTimeout(timer); };
  }, [serverId, channel, connectionId]);
  return <section className="exec-output" aria-label="Command output">
    <header><h2>Command output</h2><span role="status">{state}</span><Button size="sm" variant="ghost" onClick={onClose}>{done ? "Close output" : "Hide output"}</Button></header>{command && <pre className="exec-command" aria-label="Executed command">{command}</pre>}
    <pre tabIndex={0} aria-label="Execution output">{output || "Waiting for output…"}</pre>
    {error && <p role="alert">{error}</p>}
    <div className="oars-data-actions">
      <Button size="sm" variant="outline" disabled={!output} onClick={async () => { try { await navigator.clipboard.writeText(output); } catch (e) { setError(`Could not copy output: ${String(e)}`); } }}>Copy output</Button>
      {!done && <Button size="sm" variant="outline" disabled={stopping} onClick={async () => {
        setStopping(true);
        try { await api.ssh.closeChannel(serverId, channel, connectionId); setState("Stop requested; remote termination is not confirmed"); finish(null); }
        catch (e) { setError(e instanceof Error ? e.message : String(e)); }
        finally { setStopping(false); }
      }}>Stop command</Button>}
      <span className="muted">Most recent 256 KB</span>
    </div>
  </section>;
}
