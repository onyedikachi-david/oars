import { useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

export function HistoryTab() {
  const [entries, setEntries] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try { const r:any = await api.history.list({}); setEntries(r.entries ?? r.history ?? r.items ?? []); } catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }
    try { const r:any = await api.history.auditList(); setAudit(r.entries ?? r.audit ?? []); } catch{}
  };
  useEffect(()=>{ load(); }, []);

  return (
    <div style={{ display:"flex", flexDirection:"column", flex:1, minHeight:0 }}>
      <div style={{ display:"flex", gap:8, padding:"10px 12px", borderBottom:"1px solid var(--border)" }}>
        <button className="btn" onClick={load}>Refresh</button>
        <button className="btn" onClick={async()=>{ if(!confirm("Clear audit log?")) return; try{ await api.history.auditClear(); load(); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Clear audit</button>
      </div>
      {error && <div className="form-error" style={{ margin:"8px 12px" }}>{error}</div>}
      <div style={{ padding:12, display:"grid", gap:16, overflow:"auto" }}>
        <div>
          <div style={{ fontWeight:600, fontSize:13 }}>Command history ({entries.length})</div>
          {entries.map((e:any,i:number)=>(
            <div key={e.id ?? i} style={{ border:"1px solid var(--border)", borderRadius:6, padding:"8px 10px", marginTop:6, background:"var(--bg-elevated)", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ fontFamily:"var(--mono)", fontSize:11 }}>{e.command ?? e.text ?? JSON.stringify(e).slice(0,120)}</span>
              <button className="btn" style={{ fontSize:11, padding:"2px 6px" }} onClick={async()=>{ try{ const r:any = await api.history.replay(e.id); setError(`Replay: ${JSON.stringify(r).slice(0,200)}`);}catch(err){ setError(err instanceof BridgeError? err.message:String(err)); }}}>Replay</button>
            </div>
          ))}
          {entries.length===0 && <div className="muted" style={{ fontSize:11 }}>No history yet</div>}
        </div>
        <div>
          <div style={{ fontWeight:600, fontSize:13 }}>Audit log ({audit.length})</div>
          {audit.map((a:any,i:number)=>(
            <div key={i} className="muted" style={{ fontSize:11, borderBottom:"1px solid var(--border)", padding:"4px 0" }}>{a.action ?? a.type} · {a.server_id ?? ""} · {a.detail?.slice(0,120) ?? ""}</div>
          ))}
          {audit.length===0 && <div className="muted" style={{ fontSize:11 }}>No audit entries</div>}
        </div>
      </div>
    </div>
  );
}
