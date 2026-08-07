import { useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

export function AgentTab() {
  const [agents, setAgents] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try { const r:any = await api.agent.list(); setAgents(r.agents ?? r.sockets ?? []); } catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }
  };
  useEffect(()=>{ load(); }, []);

  return (
    <div style={{ padding:12, display:"grid", gap:12 }}>
      <div style={{ display:"flex", gap:8 }}>
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div style={{ border:"1px solid var(--border)", borderRadius:8, padding:12, background:"var(--bg-elevated)" }}>
        <div style={{ fontWeight:600, fontSize:13 }}>SSH Agent</div>
        <div className="muted" style={{ fontSize:11 }}>UNIX socket at $SSH_AUTH_SOCK — forwarded per server via oars.agent.forward. Jump hosts via ProxyJump chain (spec 18).</div>
        <div style={{ marginTop:8, display:"grid", gap:6 }}>
          {agents.map((a:any,i:number)=>(
            <div key={i} style={{ fontFamily:"var(--mono)", fontSize:11, border:"1px solid var(--border)", borderRadius:6, padding:"6px 8px", background:"var(--bg)" }}>{a.path ?? a.socket ?? JSON.stringify(a)}</div>
          ))}
          {agents.length===0 && <div className="muted" style={{ fontSize:11 }}>No agent sockets visible — start ssh-agent or set SSH_AUTH_SOCK</div>}
        </div>
      </div>
      <div style={{ border:"1px solid var(--border)", borderRadius:8, padding:12, background:"var(--bg-elevated)" }}>
        <div style={{ fontWeight:600, fontSize:13 }}>Forwarding per server</div>
        <div className="muted" style={{ fontSize:11 }}>Toggled from the server form (auth method key + agent). The bridge validates the chain has no cycles and uses password only for the final hop.</div>
      </div>
    </div>
  );
}
