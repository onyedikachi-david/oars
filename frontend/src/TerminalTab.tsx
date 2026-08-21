import { useEffect, useRef, useState } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import "xterm/css/xterm.css";
import { api, BridgeError, vault } from "./bridge";
import type { Server, SessionStatus } from "./types";
import { STATUS_LABEL } from "./types";
import { AlertTriangle, Copy, ShieldCheck, X } from "lucide-react";
import { Button } from "./components/ui/button";
import { OarsLoadingState } from "./components/OarsLoadingState";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";

const POLL_MS = 80;
const INPUT_BUFFER_MAX = 256 * 1024;
const INPUT_CHUNK_SIZE = 8 * 1024;

// Terminal canvas renders the remote host — ANSI palette stays standard
// so `ls --color` / editor themes look correct. The chrome around it is
// the calm mineral-paper studio (see index.css: .terminal-shell).
const ANSI_THEME = {
  background: "#0f1318",
  foreground: "#dbe2ea",
  cursor: "#7aa8ff",
  cursorAccent: "#0f1318",
  selectionBackground: "rgba(122, 168, 255, 0.28)",
  black: "#1c2128",
  red: "#ff5f56",
  green: "#98c379",
  yellow: "#e5c07b",
  blue: "#61afef",
  magenta: "#c678dd",
  cyan: "#56b6c2",
  white: "#abb2bf",
  brightBlack: "#5c6370",
  brightRed: "#ff6c66",
  brightGreen: "#b5e890",
  brightYellow: "#ffd866",
  brightBlue: "#82b4ff",
  brightMagenta: "#d98ce0",
  brightCyan: "#6fd3de",
  brightWhite: "#e8ecf2",
};

interface Props {
  server: Server;
  onStatus: (serverId: string, status: SessionStatus) => void;
  onServerUpdated?: (server: Server) => void;
}

function fingerprintForDisplay(raw: string): string {
  return raw.trim();
}

function changedKeyDetails(message: string | null): { oldFingerprint: string; newFingerprint: string } | null {
  if (!message) return null;
  const match = message.match(/old:\s*([^,]+),\s*new:\s*([^;)]+)/i);
  if (!match) return null;
  return { oldFingerprint: match[1].trim(), newFingerprint: match[2].trim() };
}

export function TerminalTab({ server, onStatus, onServerUpdated }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const serverRef = useRef(server);
  serverRef.current = server;
  const [status, setStatus] = useState<SessionStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [trust, setTrust] = useState<{ fingerprint: string; algorithm?: string } | null>(null);
  const [dropped, setDropped] = useState(false);
  const [copied, setCopied] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const [retrustOpen, setRetrustOpen] = useState(false);
  const [retrustConfirm, setRetrustConfirm] = useState("");
  const [retrustBusy, setRetrustBusy] = useState(false);
  const [retrustError, setRetrustError] = useState<string | null>(null);
  const statusRef = useRef<SessionStatus>("connecting");
  const errorRef = useRef<string | null>(null);
  const trustShownRef = useRef(false);
  // Per-channel cursors for this tab instance — enables true mirrored views:
  // each tab polls with its own cursor map; the backend's Stream.view is
  // non-destructive (spec 02 §5) so no tab steals another's deltas.
  const cursorsRef = useRef<Map<number, number>>(new Map());

  useEffect(() => {
    statusRef.current = status;
    errorRef.current = error;
    onStatus(server.id, status);
  }, [status, error, server.id, onStatus]);

  const connectRef = useRef<() => Promise<void>>(async () => {});

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    let disposed = false;

    const term = new Terminal({
      fontFamily: `ui-monospace, "SF Mono", SFMono-Regular, Menlo, monospace`,
      fontSize: 13,
      lineHeight: 1.25,
      cursorBlink: true,
      scrollback: 8000,
      theme: ANSI_THEME,
      allowTransparency: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    try { fit.fit(); } catch {}
    termRef.current = term;
    term.focus();

    let inputBuffer = "";
    let sendingInput = false;

    const flushInput = async () => {
      if (disposed || sendingInput || statusRef.current !== "ready") return;
      sendingInput = true;
      while (!disposed && statusRef.current === "ready" && inputBuffer.length > 0) {
        const chunk = inputBuffer.slice(0, INPUT_CHUNK_SIZE);
        try {
          await api.ssh.input(server.id, chunk);
          inputBuffer = inputBuffer.slice(chunk.length);
          setInputError(null);
        } catch (e) {
          const message = e instanceof BridgeError ? e.message : String(e);
          if (!/session not ready|not connected/i.test(message)) {
            setInputError(`Terminal input could not be sent: ${message}`);
          }
          break;
        }
      }
      sendingInput = false;
    };

    // Keyboard: hold Cmd+Shift+K to clear the viewport (client-side only).
    const onWindowKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.shiftKey && e.key.toLowerCase() === "k") {
        // Only when the terminal is focused — don't hijack Cmd+Shift+K elsewhere.
        if (document.activeElement && host.contains(document.activeElement)) {
          e.preventDefault();
          term.clear();
        } else if (term.element && term.element.contains(document.activeElement)) {
          e.preventDefault();
          term.clear();
        }
      }
    };
    window.addEventListener("keydown", onWindowKey);

    const inputDisposable = term.onData((data) => {
      if (inputBuffer.length + data.length > INPUT_BUFFER_MAX) {
        setInputError("Terminal input is paused because the local input buffer is full.");
        return;
      }
      inputBuffer += data;
      void flushInput();
    });

    let pollTimer: ReturnType<typeof setTimeout> | null = null;
    let firstPoll = true;
    let finished = false;
    let polling = false;
    let sawSession = false;

    const poll = async () => {
      if (disposed || polling) return;
      polling = true;
      try {
        // First poll replays the retained buffer so a fresh/mirrored tab
        // sees history. Later polls carry this tab's cursors independently.
        const cursors = firstPoll ? undefined : Array.from(cursorsRef.current.entries()).map(([channel, cursor]) => ({ channel, cursor }));
        const r = await api.ssh.poll(server.id, cursors, firstPoll);
        firstPoll = false;

        if (r.status !== "closed") sawSession = true;

        if (r.status !== statusRef.current) {
          const previousStatus = statusRef.current;
          statusRef.current = r.status;
          setStatus(r.status);
          if (r.status === "error") setError(r.error ?? "connection error");
          if (r.status === "closed" && sawSession && previousStatus !== "closed" && !errorRef.current) {
            term.writeln("\r\n\x1b[38;2;139;151;166m[connection closed]\x1b[0m");
          }
          // Mirror the error text when host key changed — backend includes
          // old + new fingerprints in the error string (spec 02 §4.2).
          if (r.status === "error" && r.error && r.error.includes("host key changed")) {
            setError(r.error);
          }
        }
        if (r.status === "error" && r.error && r.error !== errorRef.current) setError(r.error);

        if (r.status === "needs_trust" && !trustShownRef.current) {
          trustShownRef.current = true;
          setTrust({ fingerprint: r.trust?.fingerprint ?? "", algorithm: r.trust?.algorithm });
        }
        if (r.status !== "needs_trust" && trustShownRef.current && (r.status === "ready" || r.status === "error" || r.status === "closed")) {
          trustShownRef.current = false;
          setTrust(null);
        }

        for (const ch of r.channels) {
          // Advance this tab's cursor to the server's response cursor.
          cursorsRef.current.set(ch.id, ch.cursor);
          if (ch.kind === "shell" && ch.data.length > 0) term.write(ch.data);
          if (ch.dropped > 0 && ch.kind === "shell") {
            setDropped(true);
            setTimeout(() => setDropped(false), 4000);
          }
        }

        if (r.status === "ready") void flushInput();

        if (r.status === "closed" && sawSession) finished = true;
      } catch (e) {
        if (!disposed) {
          setStatus("error");
          setError(e instanceof BridgeError ? e.message : String(e));
        }
      }
      polling = false;
      if (!disposed && !finished) pollTimer = setTimeout(poll, POLL_MS);
    };

    const connect = async () => {
      const priorStatus = statusRef.current;
      setError(null);
      setInputError(null);
      trustShownRef.current = false;
      setTrust(null);
      setStatus("connecting");
      cursorsRef.current.clear();
      inputBuffer = "";
      statusRef.current = "connecting";
      term.reset();
      try {
        const profile = serverRef.current;
        let password: string | undefined;
        let passphrase: string | undefined;
        if (profile.auth_method === "password") {
          const secret = await vault.get(profile.id);
          if (!secret) {
            setStatus("error");
            setError("No password stored — edit the connection profile to set one");
            return;
          }
          password = secret;
        } else if (profile.key_has_passphrase) {
          const secret = await vault.get(profile.id);
          if (!secret) {
            setStatus("error");
            setError("Key passphrase not stored — edit the connection profile to set it");
            return;
          }
          passphrase = secret;
        }
        if (priorStatus === "error" || priorStatus === "closed") {
          await api.ssh.disconnect(server.id).catch(() => {});
        }
        sawSession = false;
        finished = false;
        firstPoll = true;
        cursorsRef.current.clear();
        await api.ssh.connect(profile.id, password, passphrase);
        if (!disposed && !polling) poll();
      } catch (e) {
        if (e instanceof BridgeError && /already connected/i.test(e.message)) {
          finished = false;
          if (!disposed && !polling) poll();
        } else {
          setStatus("error");
          setError(e instanceof BridgeError ? e.message : String(e));
        }
      }
    };
    connectRef.current = connect;
    void connect();

    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
        const dims = fit.proposeDimensions();
        if (dims) api.ssh.resize(server.id, dims.cols, dims.rows).catch(() => {});
      } catch {}
    });
    ro.observe(host);
    // Initial resize after open
    requestAnimationFrame(() => {
      try {
        fit.fit();
        const d = fit.proposeDimensions();
        if (d) api.ssh.resize(server.id, d.cols, d.rows).catch(() => {});
      } catch {}
    });

    return () => {
      disposed = true;
      finished = true;
      connectRef.current = async () => {};
      if (pollTimer) clearTimeout(pollTimer);
      ro.disconnect();
      window.removeEventListener("keydown", onWindowKey);
      inputDisposable.dispose();
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server.id]);

  const handleConnect = () => void connectRef.current();
  const handleDisconnect = async () => {
    setInputError(null);
    await api.ssh.disconnect(server.id).catch(() => {});
  };
  const handleTrust = async (accept: boolean) => {
    const fp = trust?.fingerprint ?? "";
    setTrust(null);
    try {
      await api.ssh.trust(server.id, accept);
      if (!accept) {
        statusRef.current = "closed";
        setStatus("closed");
        await api.ssh.disconnect(server.id).catch(() => {});
      } else {
        // Accept persists the fingerprint; poll will move to authenticating → ready
        trustShownRef.current = false;
      }
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
      // Keep fingerprint visible on failure so user can compare
      if (fp) setTrust({ fingerprint: fp });
    }
  };
  const copyFingerprint = async () => {
    const fp = trust ? fingerprintForDisplay(trust.fingerprint) : "";
    if (!fp) return;
    try {
      await navigator.clipboard.writeText(fp);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {}
  };

  const isConnected = status === "ready" || status === "connecting" || status === "authenticating" || status === "needs_trust";
  const connectionBusy = status === "connecting" || status === "authenticating";
  const displayFp = trust ? fingerprintForDisplay(trust.fingerprint) : "";
  const changedKey = changedKeyDetails(error);

  const handleRetrust = async () => {
    if (retrustConfirm !== server.name) return;
    setRetrustBusy(true);
    setRetrustError(null);
    try {
      const result = await api.ssh.retrust(server.id, retrustConfirm);
      onServerUpdated?.(result.server);
      setRetrustOpen(false);
      setRetrustConfirm("");
      await connectRef.current();
    } catch (e) {
      setRetrustError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setRetrustBusy(false);
    }
  };

  return (
    <div className="terminal-shell">
      <div className="terminal-chrome">
        <div className="terminal-title">
          <span className="terminal-name">{server.name}</span>
          <span className="terminal-addr">{server.user}@{server.host}:{server.port}</span>
        </div>
        <span className={`terminal-status ${status === "error" ? "is-error" : ""}`}>
          <span className={`fleet-dot ${status === "ready" ? "fleet-dot-ready" : status === "error" ? "fleet-dot-error" : status === "needs_trust" ? "fleet-dot-needs_trust" : status === "closed" ? "fleet-dot-offline" : "fleet-dot-connecting"}`} aria-hidden />
          <span className="terminal-status-label">{status === "error" ? (changedKey ? "Host identity changed" : error ?? "Error") : STATUS_LABEL[status]}</span>
        </span>
        <div className="terminal-actions">
          {isConnected ? (
            <Button variant="ghost" size="sm" onClick={handleDisconnect}>Disconnect</Button>
          ) : (
            <Button size="sm" onClick={handleConnect}>Connect</Button>
          )}
        </div>
      </div>
      <div
        className="terminal-host"
        ref={hostRef}
        onClick={() => termRef.current?.focus()}
        role="application"
        aria-label={`Terminal for ${server.name}`}
      />
      {connectionBusy && (
        <OarsLoadingState
          compact
          className="terminal-loading"
          title={status === "authenticating" ? "Checking credentials" : `Connecting to ${server.name}`}
          detail="The terminal will be ready as soon as the secure session opens."
        />
      )}
      {dropped && <div className="terminal-toast" role="status">Output buffer overflowed — some lines were dropped</div>}
      {inputError && <div className="terminal-banner terminal-banner-error" role="alert">{inputError}</div>}
      {error && status === "error" && /host key changed/i.test(error) && (
        <div className="terminal-banner terminal-banner-error" role="alert">
          <AlertTriangle aria-hidden />
          <span><strong>Host identity changed.</strong> Oars stopped the connection because the stored fingerprint does not match.</span>
          <Button variant="destructive" size="sm" onClick={() => { setRetrustOpen(true); setRetrustError(null); }}>Review identity</Button>
        </div>
      )}
      {retrustOpen && (
        <RetrustModal
          server={server}
          changedKey={changedKey}
          retrustConfirm={retrustConfirm}
          setRetrustConfirm={setRetrustConfirm}
          retrustBusy={retrustBusy}
          retrustError={retrustError}
          onClose={() => setRetrustOpen(false)}
          onRetrust={handleRetrust}
        />
      )}
      {trust && (
        <TrustModal
          server={server}
          trust={trust}
          displayFp={displayFp}
          copied={copied}
          copyFingerprint={copyFingerprint}
          handleTrust={handleTrust}
        />
      )}
    </div>
  );
}

function RetrustModal({
  server,
  changedKey,
  retrustConfirm,
  setRetrustConfirm,
  retrustBusy,
  retrustError,
  onClose,
  onRetrust,
}: {
  server: Server;
  changedKey: { oldFingerprint?: string; newFingerprint?: string } | null;
  retrustConfirm: string;
  setRetrustConfirm: (val: string) => void;
  retrustBusy: boolean;
  retrustError: string | null;
  onClose: () => void;
  onRetrust: () => void;
}) {
  const dialogRef = useModalFocus(onClose, `#retrust-${server.id}`, !retrustBusy);
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !retrustBusy) onClose(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="retrust-title" aria-describedby="retrust-desc">
        <div className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon oars-modal-icon-danger" aria-hidden><AlertTriangle /></span>
            <div>
              <h2 id="retrust-title">Review changed host identity</h2>
              <p id="retrust-desc" className="oars-modal-subtitle">A changed key can mean that the server was rebuilt, or that another system is intercepting the connection.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" disabled={retrustBusy} onClick={onClose} className="oars-modal-close"><X /></Button>
          </div>
        </div>
        <div className="oars-modal-body">
          <div className="retrust-resource">
            <strong>{server.name}</strong>
            <code>{server.user}@{server.host}:{server.port}</code>
          </div>
          <div className="retrust-fingerprints">
            <div><span>Stored fingerprint</span><code>{changedKey?.oldFingerprint ?? server.host_fingerprint ?? "Unknown"}</code></div>
            <div><span>Presented fingerprint</span><code>{changedKey?.newFingerprint ?? "Unknown"}</code></div>
          </div>
          <p className="oars-hint oars-hint-warn">Verify the new fingerprint through a trusted channel. Clearing the stored key makes the next connection ask for approval again.</p>
          <div className="oars-field">
            <label htmlFor={`retrust-${server.id}`}>Type <strong>{server.name}</strong> to continue</label>
            <input id={`retrust-${server.id}`} type="text" value={retrustConfirm} onChange={(event) => setRetrustConfirm(event.target.value)} autoComplete="off" />
          </div>
          {retrustError && <div className="oars-form-error" role="alert">{retrustError}</div>}
          <div className="oars-modal-actions retrust-actions">
            <Button variant="ghost" disabled={retrustBusy} onClick={onClose}>Cancel</Button>
            <Button variant="destructive" disabled={retrustBusy || retrustConfirm !== server.name} onClick={onRetrust}>{retrustBusy ? "Clearing…" : "Clear stored key"}</Button>
          </div>
        </div>
      </div>
    </ApplicationOverlay>
  );
}

function TrustModal({
  server,
  trust,
  displayFp,
  copied,
  copyFingerprint,
  handleTrust,
}: {
  server: Server;
  trust: { algorithm?: string; fingerprint: string };
  displayFp: string;
  copied: boolean;
  copyFingerprint: () => void;
  handleTrust: (accept: boolean) => void;
}) {
  const dialogRef = useModalFocus(() => handleTrust(false));
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) handleTrust(false); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="trust-title" aria-describedby="trust-desc" onClick={(e) => e.stopPropagation()}>
        <div className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon" aria-hidden><ShieldCheck size={16} /></span>
            <div>
              <h2 id="trust-title">Verify host key</h2>
              <p id="trust-desc" className="oars-modal-subtitle">First connection to <strong>{server.host}</strong>. Compare this identity with a trusted copy before you continue.</p>
            </div>
          </div>
        </div>
        <div className="oars-modal-body">
          <div className="trust-algorithm">
            <span>Key algorithm</span>
            <code>{trust.algorithm || "Unknown"}</code>
          </div>
          <div className="trust-fp">
            <code className="trust-fp-code" title={displayFp}>{displayFp || "—"}</code>
            <Button variant="secondary" size="sm" onClick={copyFingerprint} aria-label="Copy fingerprint"><Copy size={14} aria-hidden /> {copied ? "Copied" : "Copy"}</Button>
          </div>
          <p className="oars-hint">Accepting stores this exact <code>SHA256:…</code> fingerprint for future connections.</p>
          {displayFp && !displayFp.startsWith("SHA256:") && <p className="oars-hint oars-hint-warn">This is a legacy hexadecimal fingerprint. Oars will store the canonical OpenSSH form after verification.</p>}
          <div className="oars-modal-actions" style={{ marginTop: 4 }}>
            <span className="oars-hint">Reject disconnects without saving.</span>
            <div className="oars-modal-actions-right">
              <Button variant="ghost" onClick={() => handleTrust(false)}>Reject</Button>
              <Button onClick={() => handleTrust(true)}>Accept fingerprint</Button>
            </div>
          </div>
        </div>
      </div>
    </ApplicationOverlay>
  );
}
