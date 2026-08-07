import { useState } from "react";
import { api, BridgeError } from "./bridge";

export function VncTab({ serverId }: { serverId: string }) {
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<any>(null);

  return (
    <div style={{ display:"flex", flexDirection:"column", flex:1, minHeight:0 }}>
      <div style={{ display:"flex", gap:8, padding:"10px 12px", borderBottom:"1px solid var(--border)", flexWrap:"wrap" }}>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.vnc.probe(serverId); setInfo(r); setStatus(r.ok? "probed": JSON.stringify(r).slice(0,200)); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Probe</button>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.vnc.setup(serverId); setStatus(r.ok? "setup ok": JSON.stringify(r).slice(0,200)); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Setup</button>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.vnc.start(serverId); setInfo(r); setStatus(r.url? `Listening ${r.url}`: r.ok? "started": JSON.stringify(r).slice(0,200)); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Start</button>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.vnc.poll(serverId); setStatus(r.status ?? JSON.stringify(r).slice(0,200)); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Poll</button>
        <button className="btn" onClick={async()=>{ try{ await api.vnc.stop(serverId); setStatus("stopped"); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Stop</button>
      </div>
      {error && <div className="form-error" style={{ margin:"8px 12px" }}>{error}</div>}
      {status && <div className="muted" style={{ margin:"8px 12px", fontSize:12 }}>{status}</div>}
      <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center", padding:12 }}>
        {info?.url ? (
          <iframe src={info.url} title="VNC" style={{ width:"100%", height:"100%", minHeight:420, border:"1px solid var(--border)", borderRadius:8, background:"#000" }} />
        ) : (
          <div className="muted" style={{ textAlign:"center", fontSize:12 }}>
            VNC tunnels a remote desktop over SSH. Probe → Setup → Start to get a noVNC URL.<br/>The session is local-first and closes with the SSH channel.
          </div>
        )}
      </div>
    </div>
  );
}
