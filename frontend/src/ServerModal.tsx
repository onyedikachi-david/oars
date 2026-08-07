import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, HardDrive, KeyRound, Network, ShieldCheck, Tag, Trash2, X } from "lucide-react";
import { api, BridgeError, pickFile, vault } from "./bridge";
import type { Server, AuthMethod, ServerDraft } from "./types";
import { Button } from "./components/ui/button";

interface Props {
  server?: Server;
  servers: Server[];
  onClose: () => void;
  onSaved: (server: Server) => void;
  onDeleted?: (id: string, warning?: string) => void;
}

type FieldErrors = Partial<Record<"name" | "host" | "port" | "user" | "password" | "passphrase" | "key_path" | "group" | "tags" | "via" | "form", string>>;
type SecretState = "loading" | "present" | "absent" | "error";

function draftFromServer(server: Server): ServerDraft {
  return {
    id: server.id,
    name: server.name,
    host: server.host,
    port: server.port,
    user: server.user,
    auth_method: server.auth_method,
    key_path: server.key_path,
    key_has_passphrase: server.key_has_passphrase,
    group: server.group || undefined,
    tags: server.tags.length > 0 ? server.tags : undefined,
    via_server_id: server.via_server_id,
  };
}

function mapBridgeError(msg: string): FieldErrors {
  const m = msg.toLowerCase();
  if (m.includes("host is required") || m.includes("host must not end")) return { host: msg };
  if (m.includes("port must be")) return { port: msg };
  if (m.includes("private key") || m.includes("choose a private key")) return { key_path: msg };
  if (m.includes("tags cannot")) return { tags: msg };
  if (m.includes("group names cannot") || m.includes("groups are limited") || m.includes("group segments")) return { group: msg };
  if (m.includes("cannot connect via itself") || m.includes("jump host does not exist") || m.includes("jump chains") || m.includes("jump chain contains")) return { via: msg };
  if (m.includes("unknown auth")) return { form: msg };
  return { form: msg };
}

export function ServerModal({ server, servers, onClose, onSaved, onDeleted }: Props) {
  const editing = server !== undefined;
  const dialogRef = useRef<HTMLDivElement>(null);
  const originalSecretRef = useRef<string | null>(null);

  const [name, setName] = useState(server?.name ?? "");
  const [host, setHost] = useState(server?.host ?? "");
  const [port, setPort] = useState(String(server?.port ?? 22));
  const [user, setUser] = useState(server?.user ?? "root");
  const [authMethod, setAuthMethod] = useState<AuthMethod>(server?.auth_method ?? "password");
  const [keyPath, setKeyPath] = useState(server?.key_path ?? "");
  const [keyPassphrase, setKeyPassphrase] = useState(server?.key_has_passphrase ?? false);
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [group, setGroup] = useState(server?.group ?? "");
  const [tags, setTags] = useState<string[]>(server?.tags ?? []);
  const [tagInput, setTagInput] = useState("");
  const [via, setVia] = useState<string>(server?.via_server_id ?? "");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(busy);
  const onCloseRef = useRef(onClose);
  busyRef.current = busy;
  onCloseRef.current = onClose;
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [secretState, setSecretState] = useState<SecretState>(editing ? "loading" : "absent");
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(() => Boolean(server?.group || (server?.tags && server.tags.length > 0) || server?.via_server_id));

  useEffect(() => {
    if (!editing || !server) return;
    let cancelled = false;
    vault.get(server.id)
      .then((secret) => {
        if (cancelled) return;
        originalSecretRef.current = secret;
        setSecretState(secret === null ? "absent" : "present");
      })
      .catch(() => { if (!cancelled) setSecretState("error"); });
    return () => { cancelled = true; };
  }, [editing, server?.id]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      previous?.focus();
    };
  }, []);

  const storedSecret = secretState === "present";

  const existingGroups = useMemo(() => {
    const set = new Set<string>();
    for (const s of servers) if (s.group?.trim()) set.add(s.group.trim());
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [servers]);

  const viaOptions = useMemo(() => servers.filter((s) => s.id !== server?.id), [servers, server?.id]);

  const duplicateWarning = useMemo(() => {
    const n = name.trim().toLowerCase();
    if (!n) return null;
    const dup = servers.find((s) => s.name.trim().toLowerCase() === n && s.id !== server?.id);
    return dup ? `A connection profile named “${dup.name}” already exists.` : null;
  }, [name, servers, server?.id]);

  const addTag = (raw: string) => {
    const parts = raw.split(/[,;]+/).map((p) => p.trim()).filter(Boolean);
    if (parts.length === 0) return;
    const next: string[] = [...tags];
    for (const p of parts) {
      if (p.length === 0) continue;
      if (next.some((t) => t.toLowerCase() === p.toLowerCase())) continue;
      // control-char check — mirror backend, but surface inline
      if ([...p].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) {
        setFieldErrors((prev) => ({ ...prev, tags: "Tags cannot contain control characters." }));
        continue;
      }
      next.push(p);
    }
    setTags(next);
    setTagInput("");
    if (next.length !== tags.length) setFieldErrors((prev) => ({ ...prev, tags: undefined }));
  };

  const handlePickKey = async () => {
    try {
      const path = await pickFile("Choose a private key");
      if (path) {
        setKeyPath(path);
        setFieldErrors((prev) => ({ ...prev, key_path: undefined }));
      }
    } catch (e) {
      setFieldErrors((prev) => ({ ...prev, key_path: e instanceof BridgeError ? e.message : String(e) }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFieldErrors({});

    const errors: FieldErrors = {};
    const trimmedName = name.trim();
    const trimmedHost = host.trim();
    const trimmedUser = user.trim() || "root";
    const parsedPort = Number(port);
    if (!trimmedName) errors.name = "Enter a connection name.";
    if (!trimmedHost) errors.host = "Enter an IP address or hostname.";
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) errors.port = "Port must be a whole number from 1 to 65535.";
    if (authMethod === "key" && !keyPath.trim()) errors.key_path = "Choose a private key file.";

    const submittedTags = [...tags];
    for (const pending of tagInput.split(/[,;]+/).map((part) => part.trim()).filter(Boolean)) {
      if ([...pending].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) {
        errors.tags = "Tags cannot contain control characters.";
        break;
      }
      if (!submittedTags.some((tag) => tag.toLowerCase() === pending.toLowerCase())) submittedTags.push(pending);
    }

    const canKeepPassword = editing && server?.auth_method === "password" && secretState === "present";
    const canKeepPassphrase = editing && server?.auth_method === "key" && server.key_has_passphrase && keyPassphrase && secretState === "present";
    if (authMethod === "password" && !password && !canKeepPassword) {
      errors.password = secretState === "loading" ? "Wait for the Keychain check to finish." : "Enter the server password.";
    }
    if (authMethod === "key" && keyPassphrase && !passphrase && !canKeepPassphrase) {
      errors.passphrase = secretState === "loading" ? "Wait for the Keychain check to finish." : "Enter the private key passphrase.";
    }
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setBusy(true);
    let saved: Server;
    try {
      const payload: ServerDraft = {
        id: editing ? server!.id : undefined,
        name: trimmedName,
        host: trimmedHost,
        port: parsedPort,
        user: trimmedUser,
        auth_method: authMethod,
        key_path: authMethod === "key" ? keyPath.trim() : "",
        key_has_passphrase: authMethod === "key" && keyPassphrase,
        group: group.trim() || undefined,
        tags: submittedTags.length > 0 ? submittedTags : undefined,
        via_server_id: via || null,
      };
      saved = (await api.servers.save(payload)).server;
    } catch (err) {
      const msg = err instanceof BridgeError ? err.message : String(err);
      setFieldErrors(mapBridgeError(msg));
      setBusy(false);
      return;
    }

    try {
      if (authMethod === "password" && password) {
        await vault.set(saved.id, password);
      } else if (authMethod === "key" && keyPassphrase && passphrase) {
        await vault.set(saved.id, passphrase);
      } else if ((authMethod === "agent" || (authMethod === "key" && !keyPassphrase)) && secretState !== "absent") {
        await vault.delete(saved.id);
      }
    } catch (err) {
      let rollbackFailed = false;
      try {
        if (editing && server) {
          await api.servers.save(draftFromServer(server));
          if (originalSecretRef.current === null) await vault.delete(server.id).catch(() => {});
          else await vault.set(server.id, originalSecretRef.current);
        } else {
          await vault.delete(saved.id).catch(() => {});
          await api.servers.delete(saved.id);
        }
      } catch {
        rollbackFailed = true;
      }
      const reason = err instanceof BridgeError ? err.message : String(err);
      setFieldErrors({
        form: rollbackFailed
          ? `The connection profile was saved, but the Keychain update failed: ${reason}. Review the profile before you connect.`
          : `The Keychain update failed, so Oars did not keep the profile change: ${reason}`,
      });
      setBusy(false);
      return;
    }

    setTags(submittedTags);
    setTagInput("");
    onSaved(saved);
  };

  const handleDelete = async () => {
    if (!server) return;
    setBusy(true);
    try {
      await api.servers.delete(server.id);
      let warning: string | undefined;
      try {
        await vault.delete(server.id);
      } catch (err) {
        const reason = err instanceof BridgeError ? err.message : String(err);
        warning = `Profile removed, but its Keychain credential could not be deleted: ${reason}`;
      }
      onDeleted?.(server.id, warning);
      onClose();
    } catch (err) {
      setFieldErrors({ form: err instanceof BridgeError ? err.message : String(err) });
      setBusy(false);
      setShowDeleteConfirm(false);
    }
  };

  return (
    <div className="oars-modal-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <div
        ref={dialogRef}
        className="oars-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="oars-modal-title"
        onClick={(ev) => ev.stopPropagation()}
      >
        <div className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon" aria-hidden>
              {editing ? <HardDrive size={16} /> : <Network size={16} />}
            </span>
            <div>
              <h2 id="oars-modal-title">{editing ? "Edit connection profile" : "Add connection profile"}</h2>
              <p className="oars-modal-subtitle">
                {editing ? "Update how Oars connects to this server. Secrets stay in your local Keychain." : "Save a connection profile once. Oars connects over standard SSH — no agent required."}
              </p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose} disabled={busy} className="oars-modal-close">
              <X />
            </Button>
          </div>
        </div>

        <form className="oars-modal-body" onSubmit={handleSubmit} noValidate>
          {/* Primary identity */}
          <div className="oars-field-group">
            <div className="oars-field">
              <label htmlFor="oars-name">Connection name</label>
              <input
                id="oars-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Production API"
                autoFocus
                required
                aria-invalid={Boolean(fieldErrors.name)}
                className={fieldErrors.name ? "oars-input-error" : undefined}
              />
              {duplicateWarning && <span className="oars-hint oars-hint-warn">{duplicateWarning} You can still save — names are not required to be unique.</span>}
              {fieldErrors.name && <span className="oars-field-error">{fieldErrors.name}</span>}
            </div>

            <div className="oars-row-2">
              <div className="oars-field">
                <label htmlFor="oars-host">Host</label>
                <input
                  id="oars-host"
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="192.168.1.10 or api.example.com"
                  required
                  aria-invalid={Boolean(fieldErrors.host)}
                  className={fieldErrors.host ? "oars-input-error" : undefined}
                />
                <span className="oars-hint">IP address or hostname. A trailing slash is not allowed.</span>
                {fieldErrors.host && <span className="oars-field-error">{fieldErrors.host}</span>}
              </div>
              <div className="oars-field oars-field-narrow">
                <label htmlFor="oars-port">Port</label>
                <input
                  id="oars-port"
                  type="number"
                  inputMode="numeric"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  min={1}
                  max={65535}
                  required
                  aria-invalid={Boolean(fieldErrors.port)}
                  className={fieldErrors.port ? "oars-input-error" : undefined}
                />
                {fieldErrors.port && <span className="oars-field-error">{fieldErrors.port}</span>}
              </div>
            </div>

            <div className="oars-field">
              <label htmlFor="oars-user">User</label>
              <input
                id="oars-user"
                type="text"
                value={user}
                onChange={(e) => setUser(e.target.value)}
                placeholder="root"
                required
                aria-invalid={Boolean(fieldErrors.user)}
                className={fieldErrors.user ? "oars-input-error" : undefined}
              />
              {fieldErrors.user && <span className="oars-field-error">{fieldErrors.user}</span>}
            </div>
          </div>

          {/* Authentication */}
          <div className="oars-field-group">
            <div className="oars-field">
              <span className="oars-label">Authentication</span>
              <div className="oars-segmented" role="group" aria-label="Authentication method">
                <button type="button" className={authMethod === "password" ? "is-active" : ""} onClick={() => setAuthMethod("password")}>
                  <ShieldCheck size={14} aria-hidden /> Password
                </button>
                <button type="button" className={authMethod === "key" ? "is-active" : ""} onClick={() => setAuthMethod("key")}>
                  <KeyRound size={14} aria-hidden /> SSH key
                </button>
                <button type="button" className={authMethod === "agent" ? "is-active" : ""} onClick={() => setAuthMethod("agent")}>
                  <HardDrive size={14} aria-hidden /> Agent
                </button>
              </div>
              <span className="oars-hint">
                {authMethod === "password" && "Password is stored in your system Keychain, never in the config file."}
                {authMethod === "key" && "Private key stays on disk; passphrase is kept in the Keychain."}
                {authMethod === "agent" && "Authenticates through your local SSH agent (SSH_AUTH_SOCK). No key path or passphrase needed."}
              </span>
            </div>

            {authMethod === "password" && (
              <div className="oars-field">
                <label htmlFor="oars-password">Password {editing && server?.auth_method === "password" && storedSecret && !password ? <span className="oars-inline-hint">— stored in Keychain</span> : null}</label>
                <input
                  id="oars-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={editing && server?.auth_method === "password" && storedSecret ? "Leave blank to keep the stored password" : "Server password"}
                  autoComplete="off"
                  aria-invalid={Boolean(fieldErrors.password)}
                  className={fieldErrors.password ? "oars-input-error" : undefined}
                />
                {fieldErrors.password && <span className="oars-field-error">{fieldErrors.password}</span>}
                {secretState === "error" && !password && <span className="oars-hint oars-hint-warn">Oars could not check the stored Keychain credential. Enter the password again to continue.</span>}
              </div>
            )}

            {authMethod === "key" && (
              <>
                <div className="oars-field">
                  <label htmlFor="oars-keypath">Private key</label>
                  <div className="oars-key-row">
                    <input
                      id="oars-keypath"
                      type="text"
                      value={keyPath}
                      onChange={(e) => setKeyPath(e.target.value)}
                      placeholder="~/.ssh/id_ed25519"
                      aria-invalid={Boolean(fieldErrors.key_path)}
                      className={fieldErrors.key_path ? "oars-input-error" : undefined}
                    />
                    <Button type="button" variant="secondary" size="sm" onClick={handlePickKey}>Browse…</Button>
                  </div>
                  {fieldErrors.key_path && <span className="oars-field-error">{fieldErrors.key_path}</span>}
                  <span className="oars-hint">Oars expands a leading ~/ to your home directory.</span>
                </div>
                <label className="oars-check">
                  <input type="checkbox" checked={keyPassphrase} onChange={(e) => setKeyPassphrase(e.target.checked)} />
                  <span>Key requires a passphrase</span>
                </label>
                {keyPassphrase && (
                  <div className="oars-field">
                    <label htmlFor="oars-passphrase">Passphrase {editing && server?.auth_method === "key" && server.key_has_passphrase && storedSecret && !passphrase ? <span className="oars-inline-hint">— stored in Keychain</span> : null}</label>
                    <input
                      id="oars-passphrase"
                      type="password"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      placeholder={editing && server?.auth_method === "key" && server.key_has_passphrase && storedSecret ? "Leave blank to keep the stored passphrase" : "Key passphrase"}
                      autoComplete="off"
                      aria-invalid={Boolean(fieldErrors.passphrase)}
                      className={fieldErrors.passphrase ? "oars-input-error" : undefined}
                    />
                    {fieldErrors.passphrase && <span className="oars-field-error">{fieldErrors.passphrase}</span>}
                    {secretState === "error" && !passphrase && <span className="oars-hint oars-hint-warn">Oars could not check the stored Keychain credential. Enter the passphrase again to continue.</span>}
                  </div>
                )}
              </>
            )}

            {authMethod === "agent" && (
              <div className="oars-callout">
                <p>Oars will offer keys from your SSH agent. Make sure the agent is running and the key is loaded (<code>ssh-add -l</code>). No additional fields are required.</p>
              </div>
            )}
          </div>

          {/* Organisation — progressive disclosure */}
          <div className="oars-field-group oars-field-group-soft">
            <button type="button" className="oars-disclosure" aria-expanded={advancedOpen} onClick={() => setAdvancedOpen((v) => !v)}>
              <span className="oars-disclosure-title"><Tag size={14} aria-hidden /> Organisation</span>
              <span className="oars-disclosure-hint">Group, tags, and jump host <ChevronDown className={advancedOpen ? "" : "is-collapsed"} aria-hidden /></span>
            </button>

            {advancedOpen && (
              <div className="oars-disclosure-body">
                <div className="oars-field">
                  <label htmlFor="oars-group">Group</label>
                  <input
                    id="oars-group"
                    type="text"
                    list="oars-group-list"
                    value={group}
                    onChange={(e) => setGroup(e.target.value)}
                    placeholder="production or production/api"
                    aria-invalid={Boolean(fieldErrors.group)}
                    className={fieldErrors.group ? "oars-input-error" : undefined}
                  />
                  <datalist id="oars-group-list">
                    {existingGroups.map((g) => <option key={g} value={g} />)}
                  </datalist>
                  <span className="oars-hint">One level only — <code>parent</code> or <code>parent/child</code>. Leave blank for Ungrouped.</span>
                  {fieldErrors.group && <span className="oars-field-error">{fieldErrors.group}</span>}
                </div>

                <div className="oars-field">
                  <label htmlFor="oars-tags">Tags</label>
                  <div className="oars-tags">
                    {tags.map((t) => (
                      <span key={t} className="oars-tag">
                        {t}
                        <button type="button" aria-label={`Remove ${t}`} onClick={() => setTags(tags.filter((x) => x !== t))}>
                          <X size={12} />
                        </button>
                      </span>
                    ))}
                    <input
                      id="oars-tags"
                      type="text"
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === ",") { e.preventDefault(); addTag(tagInput); }
                        if (e.key === "Backspace" && !tagInput && tags.length > 0) setTags(tags.slice(0, -1));
                      }}
                      onBlur={() => { if (tagInput.trim()) addTag(tagInput); }}
                      placeholder={tags.length === 0 ? "web, api — press Enter" : "Add another…"}
                    />
                  </div>
                  <span className="oars-hint">Free-form labels. Trimmed, deduplicated (case-insensitive), and preserved in your export.</span>
                  {fieldErrors.tags && <span className="oars-field-error">{fieldErrors.tags}</span>}
                </div>

                <div className="oars-field">
                  <label htmlFor="oars-via">Jump host</label>
                  <select
                    id="oars-via"
                    value={via}
                    onChange={(e) => setVia(e.target.value)}
                    aria-invalid={Boolean(fieldErrors.via)}
                    className={fieldErrors.via ? "oars-input-error" : undefined}
                  >
                    <option value="">Direct connection</option>
                    {viaOptions.map((s) => (
                      <option key={s.id} value={s.id}>{s.name} — {s.host}</option>
                    ))}
                  </select>
                  <span className="oars-hint">Connect via another profile. Chains up to three hops, no cycles.</span>
                  {fieldErrors.via && <span className="oars-field-error">{fieldErrors.via}</span>}
                </div>
              </div>
            )}
          </div>

          {fieldErrors.form && <div className="oars-form-error" role="alert">{fieldErrors.form}</div>}

          <div className="oars-modal-actions">
            <div className="oars-modal-actions-left">
              {editing && !showDeleteConfirm && (
                <Button type="button" variant="ghost" size="sm" onClick={() => setShowDeleteConfirm(true)} className="oars-danger-ghost">
                  <Trash2 size={14} aria-hidden /> Remove profile
                </Button>
              )}
              {editing && showDeleteConfirm && (
                <span className="oars-confirm">
                  Remove “{server?.name}”? <Button type="button" variant="destructive" size="sm" disabled={busy} onClick={handleDelete}>Remove</Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setShowDeleteConfirm(false)}>Keep</Button>
                </span>
              )}
            </div>
            <div className="oars-modal-actions-right">
              <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
              <Button type="submit" disabled={busy}>{busy ? "Saving…" : editing ? "Save changes" : "Add connection profile"}</Button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
