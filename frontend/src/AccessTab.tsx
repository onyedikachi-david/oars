import { useCallback, useState } from "react";
import { api, BridgeError } from "./bridge";

export function AccessTab() {
  const [scanId, setScanId] = useState<number | null>(null);
  const [people, setPeople] = useState<any[]>([]);
  const [unassigned, setUnassigned] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<string>("");
  const [syncErrors, setSyncErrors] = useState<any[]>([]);
  const [identities, setIdentities] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadIdentities = useCallback(async () => {
    try { const r: any = await api.access.identitiesList(); setIdentities(r.identities ?? r.id ?? [] instanceof Array ? r.identities : []); } catch {}
  }, []);

  const handleScan = async () => {
    setBusy(true); setError(null);
    try {
      const r: any = await api.access.scan();
      setScanId(r.scan_id ?? r.scanId ?? 1);
      // poll
      let attempts = 0;
      const poll = async () => {
        attempts++;
        try {
          const pr: any = await api.access.poll(r.scan_id);
          setPeople(pr.people ?? []);
          setUnassigned(pr.unassigned ?? []);
          setCoverage(pr.coverage ?? "");
          setSyncErrors(pr.sync_errors ?? pr.syncErrors ?? []);
          if (pr.state === "scanning" && attempts < 30) setTimeout(poll, 800);
          else setBusy(false);
        } catch (e) { setBusy(false); setError(e instanceof BridgeError ? e.message : String(e)); }
      };
      setTimeout(poll, 500);
      loadIdentities();
    } catch (e) { setBusy(false); setError(e instanceof BridgeError ? e.message : String(e)); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)", alignItems: "center" }}>
        <button className="btn" onClick={handleScan} disabled={busy}>{busy ? "Scanning…" : "Re-scan"}</button>
        <button className="btn" onClick={loadIdentities}>Refresh identities</button>
        <button className="btn" onClick={async () => { try { const r: any = await api.access.export("csv"); const path = r.path ?? "export.csv"; setError(`Export: ${path}`);} catch (e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Export CSV</button>
        <span className="muted" style={{ fontSize: 11 }}>{coverage ? `coverage: ${coverage}` : ""} {scanId ? `· scan #${scanId}` : ""}</span>
      </div>
      {error && <div className="form-error" style={{ margin: "8px 12px" }}>{error}</div>}
      {syncErrors.length > 0 && <div style={{ margin: "8px 12px", background: "rgba(220,60,60,0.12)", border: "1px solid rgba(220,60,60,0.3)", borderRadius: 6, padding: 8, fontSize: 12 }}>{syncErrors.length} Sync Errors — {syncErrors.map((e:any)=>e.server_id ?? e.reason).join(", ")}</div>}
      <div style={{ padding: 12, display: "grid", gap: 12, overflow: "auto" }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>People ({people.length})</div>
          {people.map((p:any)=> (
            <div key={p.identity_id ?? p.name} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, background: "var(--bg-elevated)", marginTop: 8 }}>
              <div style={{ fontWeight: 600 }}>{p.name}</div>
              <div className="muted" style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{(p.fingerprints ?? []).join(", ")}</div>
              <div style={{ display:"flex", gap: 6, flexWrap:"wrap", marginTop: 6 }}>
                {(p.grants ?? []).map((g:any,i:number)=>(
                  <span key={i} className="tag">{g.user}@{g.server_id} {g.sudo ? "(sudo)" : ""}</span>
                ))}
              </div>
              <div style={{ display:"flex", gap: 8, marginTop: 8 }}>
                <button className="btn" onClick={async()=>{ if(!confirm(`Offboard ${p.name}?`)) return; const name = prompt(`Type "${p.name}" to confirm:`); if(name!==p.name) return; try{ const r:any = await api.access.offboard(p.identity_id, p.grants ?? []); setError(`Offboard job #${r.job_id}`);} catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Offboard</button>
              </div>
            </div>
          ))}
          {people.length===0 && <div className="muted" style={{ fontSize:12 }}>No people scanned yet — hit Re-scan</div>}
        </div>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Unassigned keys ({unassigned.length})</div>
          {unassigned.map((k:any,i:number)=>(
            <div key={i} className="muted" style={{ fontSize: 11, border:"1px solid var(--border)", borderRadius:6, padding:"6px 8px", marginTop:6, fontFamily:"var(--mono)" }}>{k.fingerprint ?? k.key?.slice(0,40)} — {k.server_id ?? ""}</div>
          ))}
        </div>
        <div>
          <div style={{ fontWeight:600, fontSize:13 }}>Identities</div>
          <div style={{ display:"flex", gap:8, marginTop:6 }}>
            <button className="btn" onClick={async()=>{ const name=prompt("Person name:"); if(!name) return; const fps=prompt("Fingerprints comma-separated (SHA256:...):",""); if(!fps && fps!== "") return; const list=(fps??"").split(",").map(s=>s.trim()).filter(Boolean); try{ await api.access.identitiesSave({ name, fingerprints:list }); loadIdentities(); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Save person</button>
          </div>
          {identities.map((id:any,i:number)=>(
            <div key={i} style={{ border:"1px solid var(--border)", borderRadius:6, padding:"6px 8px", marginTop:6, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ fontSize:12 }}>{id.name} — {(id.fingerprints??[]).join(", ")}</span>
              <button className="btn" onClick={async()=>{ if(!confirm(`Delete ${id.name}?`)) return; try{ await api.access.identitiesDelete(id.id ?? id.identity_id); loadIdentities(); }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Delete</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
