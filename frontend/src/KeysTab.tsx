import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";

export function KeysTab({ serverId }: { serverId: string }) {
  const [keys, setKeys] = useState<any[]>([]);
  const [roles, setRoles] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");

  const load = useCallback(async () => {
    try {
      const r: any = await api.sshkeys.list(serverId);
      setKeys(r.keys ?? []);
      try { const rr: any = await api.sshkeys.rolesList(serverId); setRoles(rr.roles ?? rr.users ?? []); } catch {}
    } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); }
  }, [serverId]);
  useEffect(() => { load(); }, [load]);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div style={{ display: "flex", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--border)" }}>
        <input className="input" style={{ flex: 1, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "5px 8px", fontSize: 12 }} placeholder="ssh-ed25519 AAAAC3... comment" value={newKey} onChange={(e) => setNewKey(e.target.value)} />
        <button className="btn" onClick={async () => { if (!newKey.trim()) return; try { await api.sshkeys.add(serverId, newKey.trim()); setNewKey(""); load(); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Add key</button>
        <button className="btn" onClick={async () => { try { const r: any = await api.sshkeys.generate(`/tmp/oars-key-${Date.now()}`, "oars-generated"); if (r.public_key) { setNewKey(r.public_key); } } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Generate</button>
        <button className="btn" onClick={async () => { try { const r: any = await api.sshkeys.deployKey(serverId); if (r.public_key) { await navigator.clipboard.writeText(r.public_key); setError("Deploy key copied"); setTimeout(()=>setError(null),1500);} } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Deploy key</button>
      </div>
      {error && <div className="form-error" style={{ margin: "8px 12px" }}>{error}</div>}
      <div style={{ padding: 12, display: "grid", gap: 8, overflow: "auto" }}>
        {keys.map((k: any, i: number) => (
          <div key={i} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10, background: "var(--bg-elevated)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <strong style={{ fontSize: 12, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{k.type} {k.fingerprint_sha256 ?? k.fingerprint}</strong>
              <span className="muted" style={{ fontSize: 11 }}>{k.comment ?? ""}</span>
            </div>
            <div className="muted" style={{ fontSize: 11, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{k.key?.slice(0, 64)}…</div>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button className="btn" onClick={async () => { const nk = prompt("New public key (full line):", ""); if (!nk) return; try { await api.sshkeys.rotate(serverId, k.fingerprint_sha256 ?? k.fingerprint, k.expected_line_hash ?? "", nk); load(); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Rotate</button>
              <button className="btn" onClick={async () => { if (!confirm(`Revoke ${k.fingerprint_sha256 ?? k.fingerprint}?`)) return; try { await api.sshkeys.revoke(serverId, k.fingerprint_sha256 ?? k.fingerprint, k.expected_line_hash ?? ""); load(); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Revoke</button>
            </div>
          </div>
        ))}
        {keys.length === 0 && <div className="muted">No keys — file may be missing or empty</div>}
        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 12, marginTop: 4 }}>
          <div style={{ fontWeight: 600, fontSize: 12 }}>Roles</div>
          <div className="muted" style={{ fontSize: 11 }}>read-write / read-only (forced SFTP)</div>
          <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
            <button className="btn" onClick={async () => { const n = prompt("Role username:"); if (!n) return; const ro = confirm("Read-only? OK=yes Cancel=read-write"); try { await api.sshkeys.rolesCreate(serverId, n, ro); load(); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Create role</button>
          </div>
          {roles.map((r: any, i: number) => (
            <div key={i} className="muted" style={{ fontSize: 11, display: "flex", justifyContent: "space-between", border: "1px solid var(--border)", borderRadius: 6, padding: "6px 8px", marginTop: 6 }}>
              <span>{r.name ?? r.user} · {r.read_only ? "read-only" : "read-write"}</span>
              <button className="btn" style={{ fontSize: 11, padding: "2px 6px" }} onClick={async () => { if (!confirm(`Delete role ${r.name}?`)) return; try { await api.sshkeys.rolesDelete(serverId, r.name); load(); } catch (e) { setError(e instanceof BridgeError ? e.message : String(e)); } }}>Delete</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
