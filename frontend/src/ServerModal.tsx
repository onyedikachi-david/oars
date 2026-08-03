import { useEffect, useState } from "react";
import { api, BridgeError, pickFile, vault } from "./bridge";
import type { Server } from "./types";

interface Props {
  server?: Server; // undefined = create
  onClose: () => void;
  onSaved: (server: Server) => void;
}

export function ServerModal({ server, onClose, onSaved }: Props) {
  const editing = server !== undefined;
  const [name, setName] = useState(server?.name ?? "");
  const [host, setHost] = useState(server?.host ?? "");
  const [port, setPort] = useState(String(server?.port ?? 22));
  const [user, setUser] = useState(server?.user ?? "root");
  const [authMethod, setAuthMethod] = useState<"password" | "key">(
    server?.auth_method ?? "password"
  );
  const [keyPath, setKeyPath] = useState(server?.key_path ?? "");
  const [keyPassphrase, setKeyPassphrase] = useState(server?.key_has_passphrase ?? false);
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [storedSecret, setStoredSecret] = useState(false);

  useEffect(() => {
    if (!editing) return;
    vault.get(server.id).then((secret) => setStoredSecret(secret !== null));
  }, [editing, server?.id]);

  const handlePickKey = async () => {
    const path = await pickFile("Choose a private key");
    if (path) setKeyPath(path);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.servers.save({
        id: editing ? server.id : undefined,
        name: name.trim(),
        host: host.trim(),
        port: parseInt(port, 10) || 22,
        user: user.trim(),
        auth_method: authMethod,
        key_path: authMethod === "key" ? keyPath.trim() : "",
        key_has_passphrase: authMethod === "key" && keyPassphrase,
      });

      const saved = r.server;
      // Store the secret in the Keychain. A blank field leaves an
      // existing secret untouched.
      if (authMethod === "password" && password) {
        await vault.set(saved.id, password);
      } else if (authMethod === "key" && keyPassphrase && passphrase) {
        await vault.set(saved.id, passphrase);
      }
      onSaved(saved);
    } catch (err) {
      setError(err instanceof BridgeError ? err.message : String(err));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <div className="dialog-header">{editing ? "Edit server" : "Add server"}</div>
        <form className="dialog-body" onSubmit={handleSubmit}>
          <div className="form">
            <div className="row">
              <label>Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="prod-api-01"
                autoFocus
                required
              />
            </div>
            <div className="row inline">
              <div className="row">
                <label>Host</label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="192.168.1.10 or api.example.com"
                  required
                />
              </div>
              <div className="row">
                <label>Port</label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  min={1}
                  max={65535}
                  required
                />
              </div>
            </div>
            <div className="row">
              <label>User</label>
              <input
                type="text"
                value={user}
                onChange={(e) => setUser(e.target.value)}
                placeholder="root"
                required
              />
            </div>
            <div className="row">
              <label>Authentication</label>
              <div className="segmented">
                <button
                  type="button"
                  className={authMethod === "password" ? "active" : ""}
                  onClick={() => setAuthMethod("password")}
                >
                  Password
                </button>
                <button
                  type="button"
                  className={authMethod === "key" ? "active" : ""}
                  onClick={() => setAuthMethod("key")}
                >
                  SSH key
                </button>
              </div>
            </div>

            {authMethod === "password" ? (
              <div className="row">
                <label>Password {editing && storedSecret && !password ? "(stored in Keychain)" : ""}</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={editing && storedSecret ? "Leave blank to keep existing" : "Server password"}
                />
              </div>
            ) : (
              <>
                <div className="row">
                  <label>Private key</label>
                  <div className="key-row">
                    <input
                      type="text"
                      value={keyPath}
                      onChange={(e) => setKeyPath(e.target.value)}
                      placeholder="~/.ssh/id_ed25519"
                    />
                    <button type="button" onClick={handlePickKey}>
                      Browse…
                    </button>
                  </div>
                </div>
                <label className="check-row">
                  <input
                    type="checkbox"
                    checked={keyPassphrase}
                    onChange={(e) => setKeyPassphrase(e.target.checked)}
                  />
                  Key requires a passphrase
                </label>
                {keyPassphrase && (
                  <div className="row">
                    <label>Passphrase {editing && storedSecret && !passphrase ? "(stored in Keychain)" : ""}</label>
                    <input
                      type="password"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      placeholder={editing && storedSecret ? "Leave blank to keep existing" : "Key passphrase"}
                    />
                  </div>
                )}
              </>
            )}

            {error && <div className="form-error">{error}</div>}
          </div>
          <div className="dialog-actions" style={{ padding: "18px 0 0" }}>
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? "Saving…" : editing ? "Save changes" : "Add server"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
