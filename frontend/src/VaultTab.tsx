import { useState } from "react";
import { api, BridgeError } from "./bridge";

export function VaultTab() {
  const [pw, setPw] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <div style={{ padding:12, display:"grid", gap:16, overflow:"auto" }}>
      <div style={{ border:"1px solid var(--border)", borderRadius:8, padding:12, background:"var(--bg-elevated)" }}>
        <div style={{ fontWeight:600, fontSize:13 }}>Export vault</div>
        <div className="muted" style={{ fontSize:11 }}>Encrypted .oarsvault — PBKDF2 600k + AES-256-GCM + HMAC. Plain backup never written.</div>
        <div style={{ display:"flex", gap:8, marginTop:8 }}>
          <input type="password" placeholder="Export password (min 8 chars)" value={pw} onChange={(e)=> setPw(e.target.value)} style={{ flex:1, border:"1px solid var(--border)", borderRadius:6, padding:"6px 8px", fontSize:12, background:"var(--bg)" }} />
          <button className="btn" onClick={async()=>{ try{ const r:any = await api.vault.export(pw); setStatus(`Export ok — ${r.path ?? "see chosen path"}`); setError(null);}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); setStatus(null);} }}>Export…</button>
        </div>
      </div>
      <div style={{ border:"1px solid var(--border)", borderRadius:8, padding:12, background:"var(--bg-elevated)" }}>
        <div style={{ fontWeight:600, fontSize:13 }}>Import vault</div>
        <div style={{ display:"flex", gap:8, marginTop:8, flexDirection:"column" }}>
          <input type="password" placeholder="Import password" value={pw} onChange={(e)=> setPw(e.target.value)} style={{ border:"1px solid var(--border)", borderRadius:6, padding:"6px 8px", fontSize:12, background:"var(--bg)" }} />
          <div style={{ display:"flex", gap:8 }}>
            <button className="btn" onClick={async()=>{ try{
              // Ask native to pick file: use dialog
              const picked = await (window as any).zero?.invoke("native-sdk.dialog.openFile", { title:"Pick .oarsvault" });
              const path = picked?.[0];
              if (!path) return;
              const r:any = await api.vault.import({ path, password: pw });
              setToken(r.token ?? null);
              setPreview(r.preview ?? r);
              setStatus(r.token? "Preview ready — confirm to apply":"Import done");
              setError(null);
            }catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Pick & preview</button>
            {token && <><button className="btn" onClick={async()=>{ try{ await api.vault.importConfirm(token, true); setStatus("Import applied"); setToken(null);}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Confirm import</button>
            <button className="btn" onClick={async()=>{ try{ await api.vault.importConfirm(token, false); setStatus("Import cancelled"); setToken(null);}catch(e){ setError(e instanceof BridgeError? e.message:String(e)); }}}>Cancel</button></>}
          </div>
          {preview && <pre style={{ fontSize:11, fontFamily:"var(--mono)", whiteSpace:"pre-wrap", wordBreak:"break-all", background:"var(--bg)", border:"1px solid var(--border)", borderRadius:6, padding:8 }}>{JSON.stringify(preview, null, 2).slice(0,4000)}</pre>}
        </div>
      </div>
      {status && <div className="muted" style={{ fontSize:12 }}>{status}</div>}
      {error && <div className="form-error">{error}</div>}
    </div>
  );
}
