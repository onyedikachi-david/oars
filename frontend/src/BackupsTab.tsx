import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

export function BackupsTab({ serverId }: { serverId: string }) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<any | null>(null);
  const [runStatus, setRunStatus] = useState<string>("");

  const load = useCallback(async () => {
    try { const r: any = await api.backup.list(serverId); setJobs(r.jobs ?? r.backups ?? []); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); }
  }, [serverId]);
  useEffect(()=>{ load(); }, [load]);

  const handleSave = async () => {
    if (!editing?.name || !editing?.paths) { setError("Name and paths required"); return; }
    try {
      const job = {
        id: editing.id,
        server_id: serverId,
        name: editing.name,
        paths: typeof editing.paths === "string" ? editing.paths.split(",").map((s:string)=>s.trim()).filter(Boolean) : editing.paths,
        schedule: editing.schedule ?? "daily",
        retention_days: Number(editing.retention_days ?? 7),
        s3: editing.s3,
      };
      await api.backup.save(job);
      setEditing(null); load();
    } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); }
  };

  return (
    <div style={{ display:"flex", flexDirection:"column", flex:1, minHeight:0 }}>
      <div style={{ display:"flex", gap:8, padding:"10px 12px", borderBottom:"1px solid var(--border)" }}>
        <button className="btn" onClick={()=> setEditing({ name:"", paths:"/var/www", schedule:"daily", retention_days:7 })}>+ New backup</button>
        <button className="btn" onClick={load}>Refresh</button>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.backup.install(serverId); setError(r.ok? "Install issued":"install failed"); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Install agent</button>
        <button className="btn" onClick={async()=>{ try{ const r:any = await api.backup.cronStatus(serverId); setError(JSON.stringify(r)); setTimeout(()=>setError(null),3000);}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Cron status</button>
      </div>
      {error && <div className="form-error" style={{ margin:"8px 12px" }}>{error}</div>}
      {runStatus && <div className="muted" style={{ margin:"8px 12px", fontSize:12 }}>{runStatus}</div>}
      <div style={{ padding:12, display:"grid", gap:8, overflow:"auto" }}>
        {jobs.map((j:any)=>(
          <div key={j.id} style={{ border:"1px solid var(--border)", borderRadius:8, padding:10, background:"var(--bg-elevated)" }}>
            <div style={{ display:"flex", justifyContent:"space-between" }}>
              <strong>{j.name}</strong>
              <span className="muted" style={{ fontSize:11 }}>{j.schedule} · keep {j.retention_days}d</span>
            </div>
            <div className="muted" style={{ fontSize:11, fontFamily:"var(--mono)" }}>{(j.paths ?? []).join(", ")}</div>
            <div style={{ display:"flex", gap:8, marginTop:8, flexWrap:"wrap" }}>
              <button className="btn" onClick={async()=>{ try{ const r:any = await api.backup.run(serverId, j.id); const runId=r.run_id ?? r.id; setRunStatus(`Run #${runId} started`); let t=0; const poll=async()=>{ t++; try{ const pr:any=await api.backup.poll(runId); setRunStatus(`Run #${runId} ${pr.status ?? pr.state}`); if((pr.status==="running"||pr.state==="running") && t<60) setTimeout(poll,800);}catch{}}; setTimeout(poll,600);}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Run now</button>
              <button className="btn" onClick={async()=>{ try{ const r:any = await api.backup.test(serverId, j.id); setError(r.ok? "Test ok": JSON.stringify(r));}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Test</button>
              <button className="btn" onClick={async()=>{ try{ const r:any = await api.backup.history(serverId, j.id); setError(`${(r.runs??[]).length} history runs`); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>History</button>
              <button className="btn" onClick={()=> setEditing({ ...j, paths: (j.paths??[]).join(", ") })}>Edit</button>
              <button className="btn" onClick={async()=>{ if(!confirm(`Delete ${j.name}?`)) return; try{ await api.backup.remove(serverId, j.id); load();}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Delete</button>
            </div>
          </div>
        ))}
        {jobs.length===0 && <div className="muted">No backup jobs — create one</div>}
      </div>
      {editing && (
        <div className="overlay" onClick={()=> setEditing(null)}>
          <div className="dialog" onClick={(e)=> e.stopPropagation()} style={{ width:560 }}>
            <div className="dialog-header">{editing.id? "Edit backup":"New backup"}</div>
            <div className="dialog-body"><div className="form">
              <div className="row"><label>Name</label><input type="text" value={editing.name ?? ""} onChange={(e)=> setEditing({ ...editing, name:e.target.value })} /></div>
              <div className="row"><label>Paths (comma)</label><input type="text" value={typeof editing.paths==="string"? editing.paths : (editing.paths??[]).join(", ")} onChange={(e)=> setEditing({ ...editing, paths:e.target.value })} /></div>
              <div className="row"><label>Schedule</label><select value={editing.schedule ?? "daily"} onChange={(e)=> setEditing({ ...editing, schedule:e.target.value })}><option value="hourly">hourly</option><option value="daily">daily</option><option value="weekly">weekly</option></select></div>
              <div className="row"><label>Retention (days)</label><input type="number" value={editing.retention_days ?? 7} onChange={(e)=> setEditing({ ...editing, retention_days: e.target.value })} /></div>
              <div style={{ display:"flex", gap:8, justifyContent:"flex-end", marginTop:12 }}>
                <button className="btn" onClick={()=> setEditing(null)}>Cancel</button>
                <button className="btn" onClick={handleSave}>Save</button>
              </div>
            </div></div>
          </div>
        </div>
      )}
    </div>
  );
}
