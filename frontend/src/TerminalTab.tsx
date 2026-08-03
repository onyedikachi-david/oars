import { useEffect, useRef, useState } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import "xterm/css/xterm.css";
import { api, BridgeError, vault } from "./bridge";
import type { Server, SessionStatus } from "./types";
import { STATUS_LABEL } from "./types";

const POLL_MS = 80;

// Terminal ANSI palette. Note: this renders the remote server's content
// (ls colors, vim themes), not our UI — so the standard ANSI green is
// kept for fidelity.
const ANSI_THEME = {
  background: "#0d1117",
  foreground: "#dbe2ea",
  cursor: "#4f8cff",
  cursorAccent: "#0d1117",
  selectionBackground: "rgba(79, 140, 255, 0.28)",
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
}

export function TerminalTab({ server, onStatus }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const [status, setStatus] = useState<SessionStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [trust, setTrust] = useState<{ fingerprint: string } | null>(null);
  const [dropped, setDropped] = useState(false);
  const statusRef = useRef<SessionStatus>("connecting");
  const errorRef = useRef<string | null>(null);
  const trustShownRef = useRef(false);

  // Keep latest values in refs so the poll loop reads fresh state.
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
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    fit.fit();
    termRef.current = term;
    term.focus();

    term.onData((data) => {
      api.ssh.input(server.id, data).catch(() => {});
    });

    let pollTimer: ReturnType<typeof setTimeout> | null = null;
    let firstPoll = true;
    let finished = false;
    let polling = false;
    // "closed" is only terminal once a live session was actually seen —
    // the first polls can race the connect bridge call and report
    // "closed" for a session that does not exist yet.
    let sawSession = false;

    const poll = async () => {
      if (disposed || polling) return;
      polling = true;
      try {
        const r = await api.ssh.poll(server.id, firstPoll);
        firstPoll = false;

        if (r.status !== "closed") sawSession = true;

        if (r.status !== statusRef.current) {
          setStatus(r.status);
          if (r.status === "error") setError(r.error ?? "connection error");
          if (
            r.status === "closed" &&
            sawSession &&
            statusRef.current !== "closed" &&
            !errorRef.current
          ) {
            term.writeln("\r\n\x1b[38;2;139;151;166m[connection closed]\x1b[0m");
          }
        }

        if (r.status === "needs_trust" && !trustShownRef.current) {
          trustShownRef.current = true;
          setTrust({ fingerprint: r.trust?.fingerprint ?? "" });
        }

        for (const ch of r.channels) {
          if (ch.data.length > 0) term.write(ch.data);
          if (ch.dropped > 0 && ch.kind === "shell") {
            setDropped(true);
            setTimeout(() => setDropped(false), 4000);
          }
        }

        if (r.status === "closed" && sawSession) {
          finished = true;
        }
      } catch (e) {
        if (!disposed) {
          setStatus("error");
          setError(e instanceof BridgeError ? e.message : String(e));
        }
      }
      polling = false;
      if (!disposed && !finished) {
        pollTimer = setTimeout(poll, POLL_MS);
      }
    };

    const connect = async () => {
      setError(null);
      trustShownRef.current = false;
      setTrust(null);
      setStatus("connecting");
      term.reset();
      try {
        let password: string | undefined;
        let passphrase: string | undefined;
        if (server.auth_method === "password") {
          const secret = await vault.get(server.id);
          if (!secret) {
            setStatus("error");
            setError("No password stored — edit the server to set one");
            return;
          }
          password = secret;
        } else if (server.key_has_passphrase) {
          const secret = await vault.get(server.id);
          if (!secret) {
            setStatus("error");
            setError("Key passphrase not stored — edit the server to set it");
            return;
          }
          passphrase = secret;
        }
        // A previous attempt may have left a session in error/closed
        // state; the manager refuses to reconnect those, so tear it
        // down first. Safe when nothing is connected.
        if (statusRef.current === "error" || statusRef.current === "closed") {
          await api.ssh.disconnect(server.id).catch(() => {});
        }
        sawSession = false;
        finished = false;
        firstPoll = true;
        await api.ssh.connect(server.id, password, passphrase);
        // Restart the poll loop if it had finished.
        if (!disposed && !polling) poll();
      } catch (e) {
        if (e instanceof BridgeError && e.message === "already connected") {
          // fine — the poll loop will pick up the live session
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
      } catch {
        // terminal not attached yet
      }
    });
    ro.observe(host);

    return () => {
      disposed = true;
      finished = true;
      connectRef.current = async () => {};
      if (pollTimer) clearTimeout(pollTimer);
      ro.disconnect();
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server.id]);

  const handleConnect = () => {
    void connectRef.current();
  };

  const handleDisconnect = async () => {
    await api.ssh.disconnect(server.id).catch(() => {});
  };

  const handleTrust = async (accept: boolean) => {
    setTrust(null);
    try {
      await api.ssh.trust(server.id, accept);
      if (!accept) {
        setStatus("closed");
        await api.ssh.disconnect(server.id).catch(() => {});
      }
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  return (
    <div className="session" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div className="session-header">
        <span className="server-name">{server.name}</span>
        <span className="server-addr">
          {server.user}@{server.host}:{server.port}
        </span>
        <span className={`status ${status === "error" ? "error-text" : ""}`}>
          <span className={`dot ${status}`} />
          {status === "error" ? (error ?? "error") : STATUS_LABEL[status]}
        </span>
        {status === "ready" || status === "connecting" || status === "authenticating" ? (
          <button className="btn danger" onClick={handleDisconnect}>
            Disconnect
          </button>
        ) : (
          <button className="btn" onClick={handleConnect}>
            Connect
          </button>
        )}
      </div>
      <div className="terminal-host" ref={hostRef} />
      {dropped && <div className="drop-notice">output buffer overflowed — some lines were dropped</div>}

      {trust && (
        <div className="overlay" onClick={() => handleTrust(false)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <div className="dialog-header">Verify host key</div>
            <div className="dialog-body">
              <p>
                This is the first time you connect to <strong>{server.host}</strong>. Its
                host key fingerprint is:
              </p>
              <div className="fingerprint">SHA256 {formatFingerprint(trust.fingerprint)}</div>
              <p>
                Compare this against the fingerprint shown when you first logged into the
                server. Accepting saves it for future connections.
              </p>
            </div>
            <div className="dialog-actions">
              <button className="btn danger" onClick={() => handleTrust(false)}>
                Reject
              </button>
              <button className="btn primary" onClick={() => handleTrust(true)}>
                Accept fingerprint
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatFingerprint(hex: string): string {
  const groups = hex.match(/.{1,4}/g) ?? [];
  return groups.join(" ");
}
