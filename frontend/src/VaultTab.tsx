import { useState } from "react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";

export function VaultTab() {
  const [pw, setPw] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <div style={{ padding: 12, display: "grid", gap: 16, overflow: "auto" }}>
      <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--card)" }}>
        <div style={{ fontWeight: 600, fontSize: 13 }}>Export vault</div>
        <div className="muted" style={{ fontSize: 11 }}>
          Encrypted .oarsvault — PBKDF2 600k + AES-256-GCM + HMAC. Plain backup never written.
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <input
            type="password"
            placeholder="Export password (min 8 chars)"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            style={{
              flex: 1,
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "6px 8px",
              fontSize: 12,
              background: "var(--background)",
              color: "var(--foreground)",
            }}
          />
          <Button
            size="sm"
            onClick={async () => {
              try {
                const r: any = await api.vault.export(pw);
                setStatus(`Export ok — ${r.path ?? "see chosen path"}`);
                setError(null);
              } catch (e) {
                setError(e instanceof BridgeError ? e.message : String(e));
                setStatus(null);
              }
            }}
          >
            Export…
          </Button>
        </div>
      </div>
      <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, background: "var(--card)" }}>
        <div style={{ fontWeight: 600, fontSize: 13 }}>Import vault</div>
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexDirection: "column" }}>
          <input
            type="password"
            placeholder="Import password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            style={{
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "6px 8px",
              fontSize: 12,
              background: "var(--background)",
              color: "var(--foreground)",
            }}
          />
          <div style={{ display: "flex", gap: 8 }}>
            <Button
              size="sm"
              variant="outline"
              onClick={async () => {
                try {
                  const picked = await (window as any).zero?.invoke("native-sdk.dialog.openFile", { title: "Pick .oarsvault" });
                  const path = picked?.[0];
                  if (!path) return;
                  const r: any = await api.vault.import({ path, password: pw });
                  setToken(r.token ?? null);
                  setPreview(r.preview ?? r);
                  setStatus(r.token ? "Preview ready — confirm to apply" : "Import done");
                  setError(null);
                } catch (e) {
                  setError(e instanceof BridgeError ? e.message : String(e));
                }
              }}
            >
              Pick & preview
            </Button>
            {token && (
              <>
                <Button
                  size="sm"
                  onClick={async () => {
                    try {
                      await api.vault.importConfirm(token, true);
                      setStatus("Import applied");
                      setToken(null);
                    } catch (e) {
                      setError(e instanceof BridgeError ? e.message : String(e));
                    }
                  }}
                >
                  Confirm import
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={async () => {
                    try {
                      await api.vault.importConfirm(token, false);
                      setStatus("Import cancelled");
                      setToken(null);
                    } catch (e) {
                      setError(e instanceof BridgeError ? e.message : String(e));
                    }
                  }}
                >
                  Cancel
                </Button>
              </>
            )}
          </div>
          {preview && (
            <pre
              style={{
                fontSize: 11,
                fontFamily: "var(--font-geist-mono, ui-monospace, monospace)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                background: "var(--background)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: 8,
              }}
            >
              {JSON.stringify(preview, null, 2).slice(0, 4000)}
            </pre>
          )}
        </div>
      </div>
      {status && <div className="muted" style={{ fontSize: 12 }}>{status}</div>}
      {error && (
        <div className="oars-form-error" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}
