import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Copy,
  FileKey2,
  FolderOpen,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCw,
  ShieldCheck,
  Trash2,
  UserRoundCog,
  X,
} from "lucide-react";
import { api, BridgeError, pickSaveFile } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { useModalFocus } from "./components/useModalFocus";
import type { SshKeyEntry, SshRole } from "./types";

type KeyDialog =
  | { kind: "add"; publicKey: string; comment: string; busy: boolean; error: string | null }
  | { kind: "generate"; destination: string; comment: string; passphrase: string; busy: boolean; error: string | null }
  | { kind: "rotate"; entry: SshKeyEntry; publicKey: string; busy: boolean; error: string | null }
  | { kind: "revoke"; entry: SshKeyEntry; busy: boolean; error: string | null }
  | { kind: "role"; name: string; readOnly: boolean; busy: boolean; error: string | null }
  | { kind: "delete-role"; role: SshRole; busy: boolean; error: string | null };

function messageOf(error: unknown): string {
  return error instanceof BridgeError ? error.message : String(error);
}

function KeyModal({ title, description, busy, onClose, children, footer }: { title: string; description: string; busy: boolean; onClose: () => void; children: ReactNode; footer: ReactNode }) {
  const ref = useModalFocus(onClose, "[data-key-first]", !busy);
  const titleId = `keys-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-title`;
  return (
    <div className="oars-modal-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <div ref={ref} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={`${titleId}-description`}>
        <header className="oars-modal-header oars-modal-title-row">
          <span className="oars-modal-icon"><KeyRound aria-hidden="true" /></span>
          <div><h2 id={titleId}>{title}</h2><p id={`${titleId}-description`} className="oars-modal-subtitle">{description}</p></div>
          <Button className="oars-modal-close" type="button" variant="ghost" size="icon-sm" aria-label="Close dialog" onClick={onClose} disabled={busy}><X /></Button>
        </header>
        <div className="oars-modal-body">{children}</div>
        <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right">{footer}</div></footer>
      </div>
    </div>
  );
}

function keyFingerprint(entry: SshKeyEntry): string {
  return entry.fingerprint_sha256 ?? "Fingerprint unavailable";
}

export function KeysTab({ serverId }: { serverId: string }) {
  const [keys, setKeys] = useState<SshKeyEntry[]>([]);
  const [roles, setRoles] = useState<SshRole[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dialog, setDialog] = useState<KeyDialog | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [keyResult, roleResult] = await Promise.all([
        api.sshkeys.list(serverId),
        api.sshkeys.rolesList(serverId).catch((failure) => {
          setError(`Keys loaded, but roles could not be read: ${messageOf(failure)}`);
          return { ok: false, roles: [] as SshRole[] };
        }),
      ]);
      setKeys(Array.isArray(keyResult.keys) ? keyResult.keys : []);
      setRoles(Array.isArray(roleResult.roles) ? roleResult.roles : []);
    } catch (failure) {
      setError(messageOf(failure));
    } finally {
      setHasLoaded(true);
      setLoading(false);
    }
  }, [serverId]);

  useEffect(() => { void load(); }, [load]);

  const parsedKeys = useMemo(() => keys.filter((entry) => entry.parsed), [keys]);
  const restrictedKeys = useMemo(() => parsedKeys.filter((entry) => Boolean(entry.options)), [parsedKeys]);

  const copyText = async (value: string, success: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(success);
    } catch {
      setError("Oars could not copy to the clipboard. Select and copy the value manually.");
    }
  };

  const addKey = async (current: Extract<KeyDialog, { kind: "add" }>) => {
    if (!current.publicKey.trim()) return setDialog({ ...current, error: "Paste a complete OpenSSH public key." });
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.sshkeys.add(serverId, current.publicKey.trim(), current.comment.trim() || undefined);
      setDialog(null);
      setNotice("The public key was added to this account.");
      await load();
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const generateKey = async (current: Extract<KeyDialog, { kind: "generate" }>) => {
    if (!current.destination.trim()) return setDialog({ ...current, error: "Choose where to save the local private key." });
    setDialog({ ...current, busy: true, error: null });
    try {
      const result = await api.sshkeys.generate(current.destination.trim(), current.comment.trim() || "oars-generated", current.passphrase || undefined, false);
      setNotice(`A local key pair was created at ${result.private_path}. Review the public key before you add it.`);
      setDialog({ kind: "add", publicKey: result.public_key, comment: current.comment, busy: false, error: null });
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const rotateKey = async (current: Extract<KeyDialog, { kind: "rotate" }>) => {
    if (!current.publicKey.trim()) return setDialog({ ...current, error: "Paste the replacement public key." });
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.sshkeys.rotate(serverId, keyFingerprint(current.entry), current.entry.line_hash, current.publicKey.trim());
      setDialog(null);
      setNotice("The key was replaced after the source line was checked.");
      await load();
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const revokeKey = async (current: Extract<KeyDialog, { kind: "revoke" }>) => {
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.sshkeys.revoke(serverId, keyFingerprint(current.entry), current.entry.line_hash);
      setDialog(null);
      setNotice("The selected key was removed. Existing SSH sessions can stay open.");
      await load();
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const createRole = async (current: Extract<KeyDialog, { kind: "role" }>) => {
    if (!current.name.trim()) return setDialog({ ...current, error: "Enter a Linux account name for this role." });
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.sshkeys.rolesCreate(serverId, current.name.trim(), current.readOnly);
      setDialog(null);
      setNotice(`${current.name.trim()} was created as a ${current.readOnly ? "read-only SFTP" : "standard SSH"} role.`);
      await load();
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const deleteRole = async (current: Extract<KeyDialog, { kind: "delete-role" }>) => {
    setDialog({ ...current, busy: true, error: null });
    try {
      await api.sshkeys.rolesDelete(serverId, current.role.name);
      setDialog(null);
      setNotice(`${current.role.name} was removed. Its home directory was kept on the server.`);
      await load();
    } catch (failure) {
      setDialog({ ...current, busy: false, error: messageOf(failure) });
    }
  };

  const chooseDestination = async (current: Extract<KeyDialog, { kind: "generate" }>) => {
    const destination = await pickSaveFile("Save the local private key", "id_ed25519");
    if (destination) setDialog({ ...current, destination });
  };

  if (loading && !hasLoaded) return <OarsLoadingState title="Loading access keys" detail="Oars is reading authorized keys and server roles." />;

  return (
    <div className="security-workspace keys-workspace">
      <header className="security-commandbar">
        <div className="security-commandbar-copy">
          <span className="security-commandbar-icon"><KeyRound aria-hidden="true" /></span>
          <div><h2>SSH access keys</h2><p>Control the public keys and managed login roles for this server.</p></div>
        </div>
        <div className="security-commandbar-actions">
          <Button variant="outline" onClick={async () => {
            try {
              const result = await api.sshkeys.deployKey(serverId);
              await copyText(result.public_key, `The deploy key from ${result.path} was copied.`);
            } catch (failure) { setError(messageOf(failure)); }
          }}><Clipboard />Copy deploy key</Button>
          <Button variant="outline" onClick={() => setDialog({ kind: "generate", destination: "", comment: "oars-generated", passphrase: "", busy: false, error: null })}><FileKey2 />Generate local key</Button>
          <Button onClick={() => setDialog({ kind: "add", publicKey: "", comment: "", busy: false, error: null })}><Plus />Add public key</Button>
        </div>
      </header>

      {loading && <OarsRefreshStatus label="Updating keys" />}
      {error && <div className="security-message is-error" role="alert"><AlertTriangle /><span>{error}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss error" onClick={() => setError(null)}><X /></Button></div>}
      {notice && <div className="security-message is-success" role="status"><CheckCircle2 /><span>{notice}</span><Button variant="ghost" size="icon-xs" aria-label="Dismiss message" onClick={() => setNotice(null)}><X /></Button></div>}

      <section className="security-summary" aria-label="Key inventory summary">
        <div><span>Authorized keys</span><strong>{parsedKeys.length}</strong><small>{keys.length - parsedKeys.length > 0 ? `${keys.length - parsedKeys.length} malformed` : "All entries parsed"}</small></div>
        <div><span>Restricted keys</span><strong>{restrictedKeys.length}</strong><small>Options limit key behavior</small></div>
        <div><span>Managed roles</span><strong>{roles.length}</strong><small>{roles.filter((role) => role.read_only).length} read-only SFTP</small></div>
      </section>

      <div className="security-layout keys-layout">
        <main className="security-panel keys-inventory" aria-labelledby="authorized-keys-title">
          <div className="security-panel-heading">
            <div><h3 id="authorized-keys-title">Authorized keys</h3><p>Each action is bound to the exact file line that Oars read.</p></div>
            <Button variant="ghost" size="sm" onClick={() => void load()} disabled={loading}><RefreshCw className={loading ? "is-spinning" : ""} />Refresh</Button>
          </div>
          <div className="security-list">
            {keys.map((entry) => entry.parsed ? (
              <article className="key-row" key={`${entry.line_index}-${entry.line_hash}`}>
                <div className="key-row-mark"><KeyRound aria-hidden="true" /></div>
                <div className="key-row-copy">
                  <div className="key-row-title"><strong>{entry.comment || "Unlabeled public key"}</strong><span>{entry.type ?? "SSH key"}{entry.bits ? ` · ${entry.bits} bit` : ""}</span></div>
                  <code title={keyFingerprint(entry)}>{keyFingerprint(entry)}</code>
                  <p>{entry.options ? `Restricted by ${entry.options}` : "Standard login key with no key-level restrictions"}</p>
                </div>
                <div className="key-row-actions">
                  <Button variant="ghost" size="icon-sm" aria-label={`Copy fingerprint for ${entry.comment || "key"}`} onClick={() => void copyText(keyFingerprint(entry), "The fingerprint was copied.")}><Copy /></Button>
                  <Button variant="outline" size="sm" onClick={() => setDialog({ kind: "rotate", entry, publicKey: "", busy: false, error: null })}><RotateCw />Rotate</Button>
                  <Button variant="destructive" size="sm" onClick={() => setDialog({ kind: "revoke", entry, busy: false, error: null })}><Trash2 />Revoke</Button>
                </div>
              </article>
            ) : (
              <article className="key-row is-malformed" key={`${entry.line_index}-${entry.line_hash}`}>
                <div className="key-row-mark"><AlertTriangle aria-hidden="true" /></div>
                <div className="key-row-copy"><div className="key-row-title"><strong>Malformed authorized_keys entry</strong><span>Line {entry.line_index + 1}</span></div><code>{entry.raw}</code><p>{entry.error || "This line could not be parsed and cannot be changed safely."}</p></div>
              </article>
            ))}
            {keys.length === 0 && <div className="security-empty"><KeyRound /><h3>No authorized keys</h3><p>This account has no readable public-key grants. Add a key when you are ready to allow SSH access.</p><Button onClick={() => setDialog({ kind: "add", publicKey: "", comment: "", busy: false, error: null })}><Plus />Add public key</Button></div>}
          </div>
        </main>

        <aside className="security-panel roles-panel" aria-labelledby="managed-roles-title">
          <div className="security-panel-heading">
            <div><h3 id="managed-roles-title">Managed roles</h3><p>Separate Linux accounts for standard SSH or restricted SFTP access.</p></div>
            <Button variant="outline" size="sm" onClick={() => setDialog({ kind: "role", name: "", readOnly: true, busy: false, error: null })}><Plus />Create role</Button>
          </div>
          <div className="role-list">
            {roles.map((role) => <article className="role-row" key={role.name}>
              <span className="role-row-icon">{role.read_only ? <ShieldCheck /> : <UserRoundCog />}</span>
              <div><strong>{role.name}</strong><p>{role.read_only ? "Read-only SFTP" : "Standard SSH"} · {role.users.length} named key{role.users.length === 1 ? "" : "s"}</p></div>
              <Button variant="ghost" size="icon-sm" aria-label={`Delete role ${role.name}`} onClick={() => setDialog({ kind: "delete-role", role, busy: false, error: null })}><Trash2 /></Button>
            </article>)}
            {roles.length === 0 && <div className="security-empty is-compact"><UserRoundCog /><h3>No managed roles</h3><p>Create a dedicated account when access should not use the connected login.</p></div>}
          </div>
        </aside>
      </div>

      {dialog?.kind === "add" && <KeyModal title="Add a public key" description="Oars validates the OpenSSH key, then appends one exact entry to this account." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void addKey(dialog)} disabled={dialog.busy || !dialog.publicKey.trim()}>Add key</Button></>}>
        <label className="security-field"><span>OpenSSH public key</span><textarea data-key-first value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, error: null })} placeholder="ssh-ed25519 AAAAC3… person@device" /></label>
        <label className="security-field"><span>Display comment <small>Optional</small></span><input value={dialog.comment} onChange={(event) => setDialog({ ...dialog, comment: event.target.value })} placeholder="person@device" /></label>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}

      {dialog?.kind === "generate" && <KeyModal title="Generate a local key" description="The private key stays at the path you choose. Oars prepares the public half for review before installation." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void generateKey(dialog)} disabled={dialog.busy || !dialog.destination.trim()}>Generate key pair</Button></>}>
        <div className="security-field"><span>Private key location</span><div className="security-input-action"><input data-key-first value={dialog.destination} onChange={(event) => setDialog({ ...dialog, destination: event.target.value })} placeholder="Choose a local file" /><Button type="button" variant="outline" onClick={() => void chooseDestination(dialog)}><FolderOpen />Choose</Button></div></div>
        <label className="security-field"><span>Key comment</span><input value={dialog.comment} onChange={(event) => setDialog({ ...dialog, comment: event.target.value })} /></label>
        <label className="security-field"><span>Passphrase <small>Optional</small></span><input type="password" value={dialog.passphrase} onChange={(event) => setDialog({ ...dialog, passphrase: event.target.value })} autoComplete="new-password" /></label>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}

      {dialog?.kind === "rotate" && <KeyModal title="Rotate this public key" description="Oars checks the exact source line before it replaces the selected key." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void rotateKey(dialog)} disabled={dialog.busy || !dialog.publicKey.trim()}>Replace key</Button></>}>
        <div className="security-resource"><KeyRound /><div><span>Current fingerprint</span><code>{keyFingerprint(dialog.entry)}</code></div></div>
        <label className="security-field"><span>Replacement public key</span><textarea data-key-first value={dialog.publicKey} onChange={(event) => setDialog({ ...dialog, publicKey: event.target.value, error: null })} placeholder="ssh-ed25519 AAAAC3… person@device" /></label>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}

      {dialog?.kind === "revoke" && <KeyModal title="Revoke this public key?" description="New SSH connections that use this key will stop working. Existing sessions can stay open." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep key</Button><Button variant="destructive" data-key-first onClick={() => void revokeKey(dialog)} disabled={dialog.busy}>Revoke key</Button></>}>
        <div className="security-resource is-danger"><Trash2 /><div><span>{dialog.entry.comment || "Unlabeled public key"}</span><code>{keyFingerprint(dialog.entry)}</code></div></div>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}

      {dialog?.kind === "role" && <KeyModal title="Create a managed role" description="Oars creates a dedicated Linux account and prepares its SSH key file with safe permissions." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Cancel</Button><Button onClick={() => void createRole(dialog)} disabled={dialog.busy || !dialog.name.trim()}>Create role</Button></>}>
        <label className="security-field"><span>Linux account name</span><input data-key-first value={dialog.name} onChange={(event) => setDialog({ ...dialog, name: event.target.value, error: null })} placeholder="deploy-readonly" /></label>
        <fieldset className="security-choice"><legend>Access policy</legend><label><input type="radio" checked={dialog.readOnly} onChange={() => setDialog({ ...dialog, readOnly: true })} /><span><strong>Read-only SFTP</strong><small>File download and listing through a forced command. No shell.</small></span></label><label><input type="radio" checked={!dialog.readOnly} onChange={() => setDialog({ ...dialog, readOnly: false })} /><span><strong>Standard SSH</strong><small>A normal login account with shell access.</small></span></label></fieldset>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}

      {dialog?.kind === "delete-role" && <KeyModal title={`Delete ${dialog.role.name}?`} description="Oars removes the Linux account but keeps its home directory on the server." busy={dialog.busy} onClose={() => setDialog(null)} footer={<><Button variant="outline" onClick={() => setDialog(null)} disabled={dialog.busy}>Keep role</Button><Button variant="destructive" data-key-first onClick={() => void deleteRole(dialog)} disabled={dialog.busy}>Delete role</Button></>}>
        <div className="security-resource is-danger"><Trash2 /><div><span>{dialog.role.read_only ? "Read-only SFTP role" : "Standard SSH role"}</span><code>{dialog.role.name}</code></div></div>
        {dialog.error && <p className="oars-modal-error" role="alert">{dialog.error}</p>}
      </KeyModal>}
    </div>
  );
}
