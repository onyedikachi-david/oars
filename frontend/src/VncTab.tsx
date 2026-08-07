import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ClipboardPaste,
  Keyboard,
  KeyRound,
  Maximize2,
  Minimize2,
  Monitor,
  RefreshCw,
  Unplug,
  X,
} from "lucide-react";
import RFB from "@novnc/novnc";
import { api, vault, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsLoadingState } from "./components/OarsLoadingState";
import {
  closedTunnelReason,
  desktopProbeLabel,
  legacyVncAuthWarning,
  VALID_VNC_PORT_MAX,
  VALID_VNC_PORT_MIN,
  validateSetupPasswords,
  validateVncPort,
} from "./vnc-state";

const DISPLAY_STORAGE_PREFIX = "oars:vnc:display:";
const VNC_VAULT_PREFIX = "vnc:";
const DISPLAY_PRESETS = [{ label: ":0", value: 0, port: 5900 }, { label: ":1", value: 1, port: 5901 }] as const;
const POLL_MS = 1200;
const CUSTOM_PORT_MIN_CHARS = 4; // user must at least type 590x

type Lifecycle =
  | "idle"
  | "probing"
  | "starting"
  | "connecting"
  | "credentials_required"
  | "connected"
  | "failed"
  | "stopped";

// noVNC detail types
interface CredentialsRequiredDetail { types?: string[] }
interface SecurityFailureDetail { status: number; reason?: string }

type ProbeState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; data: import("./types").VncProbeResult }
  | { kind: "error"; message: string };

type SetupState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "plan"; data: import("./types").VncSetupResult }
  | { kind: "executed"; data: import("./types").VncSetupResult }
  | { kind: "error"; message: string };

type CredentialDialogMode = "challenge" | "retry" | "manage";

function rememberedDisplay(serverId: string): number {
  try {
    const raw = localStorage.getItem(DISPLAY_STORAGE_PREFIX + serverId);
    if (raw === null) return 0;
    const n = Number(raw);
    if (Number.isInteger(n) && n >= 0 && n <= 64) return n;
  } catch {}
  return 0;
}
function rememberDisplay(serverId: string, display: number) {
  try { localStorage.setItem(DISPLAY_STORAGE_PREFIX + serverId, String(display)); } catch {}
}

function portFromDisplay(display: number): number { return 5900 + display; }

function messageOf(e: unknown): string { return e instanceof BridgeError ? e.message : String(e); }

function bytesLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Clip helper: single paste into the remote session.
const CLIP_LIMIT = 32 * 1024;

export function VncTab({ serverId }: { serverId: string }) {
  // ── Display / port selection
  const [display, setDisplay] = useState<number>(() => rememberedDisplay(serverId));
  const [customPortRaw, setCustomPortRaw] = useState<string>(() => String(portFromDisplay(rememberedDisplay(serverId))));
  const [useCustomPort, setUseCustomPort] = useState(false);
  const [portError, setPortError] = useState<string | null>(null);

  // Derive the port we will send to oars.vnc.start
  const derivedPort = useMemo(() => {
    if (!useCustomPort) return portFromDisplay(display);
    const parsed = validateVncPort(customPortRaw);
    return parsed.ok ? parsed.value : null;
  }, [display, useCustomPort, customPortRaw]);

  // ── Lifecycle, tunnel, polling stats
  const [lifecycle, setLifecycle] = useState<Lifecycle>("idle");
  const [lifecycleError, setLifecycleError] = useState<string | null>(null);
  const tunnelRef = useRef<{ id: number; port: number; token: string } | null>(null);
  const [tunnelId, setTunnelId] = useState<number | null>(null);
  const [pollState, setPollState] = useState<{ state: string; bytesUp: number; bytesDown: number; error: string } | null>(null);
  const startSeqRef = useRef(0);
  const rfbRef = useRef<InstanceType<typeof RFB> | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const securityFailureRef = useRef<string | null>(null);
  const lifecycleErrorRef = useRef<string | null>(null);

  // ── Credentials (in-memory only; vault write is the sole persistence)
  const [credTypes, setCredTypes] = useState<string[] | null>(null);
  const [credDialogOpen, setCredDialogOpen] = useState(false);
  const [credPassword, setCredPassword] = useState("");
  const [credRemember, setCredRemember] = useState(false);
  const [credBusy, setCredBusy] = useState(false);
  const [credDialogMode, setCredDialogMode] = useState<CredentialDialogMode>("challenge");
  const [credentialNotice, setCredentialNotice] = useState<string | null>(null);
  const [securityFailure, setSecurityFailure] = useState<string | null>(null);
  useEffect(() => { securityFailureRef.current = securityFailure; }, [securityFailure]);
  useEffect(() => { lifecycleErrorRef.current = lifecycleError; }, [lifecycleError]);

  // ── Scale
  const [fit, setFit] = useState(true);

  // ── Clipboard
  const [clipText, setClipText] = useState("");
  const [clipFeedback, setClipFeedback] = useState<string | null>(null);

  // ── Probe / Setup
  const [probe, setProbe] = useState<ProbeState>({ kind: "idle" });
  const [setup, setSetup] = useState<SetupState>({ kind: "idle" });
  const [setupApprovalOpen, setSetupApprovalOpen] = useState(false);
  const [setupBusy, setSetupBusy] = useState(false);
  const [setupExecuting, setSetupExecuting] = useState(false);
  const [setupPassword, setSetupPassword] = useState("");
  const [setupPasswordConfirm, setSetupPasswordConfirm] = useState("");
  const [setupPasswordError, setSetupPasswordError] = useState<string | null>(null);
  const [setupDesktop, setSetupDesktop] = useState(true);
  const [setupAutoConnect, setSetupAutoConnect] = useState(false);

  // ── Display memory + custom port sync
  useEffect(() => {
    const nextDisplay = rememberedDisplay(serverId);
    setDisplay(nextDisplay);
    setCustomPortRaw(String(portFromDisplay(nextDisplay)));
    setUseCustomPort(false);
    setPortError(null);
    // full teardown on server switch (also handled by unmount, but explicit)
  }, [serverId]);

  useEffect(() => {
    if (!useCustomPort) setCustomPortRaw(String(portFromDisplay(display)));
  }, [display, useCustomPort]);

  // Teardown helper: stop tunnel + disconnect RFB; idempotent.
  const stopTunnelAndRfb = useCallback(async (reason?: string) => {
    const tunnel = tunnelRef.current;
    const rfb = rfbRef.current;
    tunnelRef.current = null;
    rfbRef.current = null;
    if (rfb) { try { rfb.disconnect(); } catch {} }
    // This target is owned only by noVNC. React renders its placeholder and
    // loading state as siblings, so cleanup cannot remove React-owned nodes.
    containerRef.current?.replaceChildren();
    if (tunnel) {
      try { await api.vnc.stop(serverId, tunnel.id); } catch {}
    }
    setTunnelId(null);
    if (reason) { setLifecycleError(reason); setLifecycle("failed"); }
  }, [serverId]);

  // Poll loop while a tunnel exists.
  useEffect(() => {
    if (tunnelId == null) { setPollState(null); return; }
    let cancelled = false;
    let timer: number | null = null;
    const tick = async () => {
      try {
        const r = await api.vnc.poll(serverId, tunnelId);
        if (cancelled) return;
        setPollState({ state: r.state, bytesUp: r.bytes_up, bytesDown: r.bytes_down, error: r.error ?? "" });
        if (r.state === "closed") {
          await stopTunnelAndRfb(closedTunnelReason(r) ?? undefined);
          return;
        }
      } catch (e) {
        if (!cancelled) {
          await stopTunnelAndRfb(`VNC status check failed: ${messageOf(e)}`);
          return;
        }
      }
      if (!cancelled) timer = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => { cancelled = true; if (timer) window.clearTimeout(timer); };
  }, [serverId, tunnelId, stopTunnelAndRfb]);

  // Disconnect handler shared by effect + cleanup.
  const disconnect = useCallback(async () => {
    const seq = ++startSeqRef.current;
    void seq;
    await stopTunnelAndRfb();
    setLifecycle("stopped");
    setLifecycleError(null);
    setCredDialogOpen(false);
    setCredTypes(null);
    setSecurityFailure(null);
  }, [stopTunnelAndRfb]);

  // Unmount cleanup.
  useEffect(() => {
    return () => { void stopTunnelAndRfb(); };
  }, [stopTunnelAndRfb]);

  // Server switch cleanup (tunnel is bound to the previous server).
  useEffect(() => {
    // handled by the stopTunnelAndRfb-driven serverId effect on mount,
    // but also reset lifecycle state synchronously when serverId changes.
    setLifecycle("idle");
    setLifecycleError(null);
    setPollState(null);
    setTunnelId(null);
    tunnelRef.current = null;
    if (rfbRef.current) { try { rfbRef.current.disconnect(); } catch {}; rfbRef.current = null; }
    setCredDialogOpen(false);
    setCredTypes(null);
    setSecurityFailure(null);
  }, [serverId]);

  // ── Probe
  const runProbe = useCallback(async () => {
    setProbe({ kind: "loading" });
    try {
      const r = await api.vnc.probe(serverId, display);
      setProbe({ kind: "ready", data: r });
    } catch (e) {
      setProbe({ kind: "error", message: messageOf(e) });
    }
  }, [serverId, display]);

  useEffect(() => { void runProbe(); }, [runProbe]);

  // ── Setup: probe before setup (spec), then dry_run to approval
  const runSetupDry = useCallback(async () => {
    const installDesktop = probe.kind === "ready" ? !probe.data.desktop_running : true;
    rememberDisplay(serverId, display);
    setSetupDesktop(installDesktop);
    setSetup({ kind: "loading" });
    try {
      // Re-probe to avoid stale plan (spec says probe before setup)
      await runProbe();
      const r = await api.vnc.setup(serverId, { display, dry_run: true, installDesktop });
      setSetup({ kind: "plan", data: r });
      setSetupPassword("");
      setSetupPasswordConfirm("");
      setSetupPasswordError(null);
      setSetupApprovalOpen(true);
    } catch (e) {
      setSetup({ kind: "error", message: messageOf(e) });
    }
  }, [serverId, display, probe, runProbe]);

  const updateDesktopChoice = useCallback(async (installDesktop: boolean) => {
    setSetupDesktop(installDesktop);
    setSetupBusy(true);
    setSetupPasswordError(null);
    try {
      const r = await api.vnc.setup(serverId, { display, dry_run: true, installDesktop });
      setSetup({ kind: "plan", data: r });
    } catch (e) {
      setSetup({ kind: "error", message: messageOf(e) });
      setSetupApprovalOpen(false);
    } finally {
      setSetupBusy(false);
    }
  }, [serverId, display]);

  const executeSetup = useCallback(async () => {
    const passwordError = validateSetupPasswords(setupPassword, setupPasswordConfirm);
    if (passwordError) { setSetupPasswordError(passwordError); return; }
    setSetupBusy(true);
    setSetupExecuting(true);
    setSetupPasswordError(null);
    try {
      if (tunnelRef.current) await disconnect();
      const r = await api.vnc.setup(serverId, { display, dry_run: false, password: setupPassword, installDesktop: setupDesktop });
      await vault.set(VNC_VAULT_PREFIX + serverId, setupPassword);
      setSetup({ kind: "executed", data: r });
      setSetupApprovalOpen(false);
      setSetupPassword("");
      setSetupPasswordConfirm("");
      setCredentialNotice(setupDesktop ? "XFCE desktop configured; server password saved in Keychain" : "Server password configured and saved in Keychain");
      await runProbe();
      setSetupAutoConnect(true);
    } catch (e) {
      setSetup({ kind: "error", message: messageOf(e) });
      await runProbe();
    } finally {
      setSetupExecuting(false);
      setSetupBusy(false);
    }
  }, [serverId, display, runProbe, setupPassword, setupPasswordConfirm, setupDesktop, disconnect]);

  // ── Start tunnel + wire noVNC
  const start = useCallback(async (passwordOverride?: string) => {
    if (useCustomPort) {
      const parsed = validateVncPort(customPortRaw);
      if (!parsed.ok) { setPortError(parsed.message); return; }
    }
    if (derivedPort == null) { setPortError(`Port must be ${VALID_VNC_PORT_MIN}-${VALID_VNC_PORT_MAX}`); return; }
    setPortError(null);
    const seq = ++startSeqRef.current;
    // Tear down any previous tunnel before starting.
    await stopTunnelAndRfb();
    if (seq !== startSeqRef.current) return;
    setLifecycle("starting");
    setLifecycleError(null);
    setSecurityFailure(null);
    setPollState(null);
    rememberDisplay(serverId, display);

    let startRes: import("./types").VncStartResult;
    try {
      // Bridge contract: host + port reach the payload exactly.
      // Omit host to use the server-side default (127.0.0.1).
      startRes = await api.vnc.start(serverId, { port: derivedPort });
    } catch (e) {
      if (seq !== startSeqRef.current) return;
      setLifecycle("failed");
      setLifecycleError(messageOf(e));
      return;
    }
    if (seq !== startSeqRef.current) {
      // A newer start won; clean up the orphan tunnel.
      try { await api.vnc.stop(serverId, startRes.tunnel_id); } catch {}
      return;
    }

    tunnelRef.current = { id: startRes.tunnel_id, port: startRes.ws_port, token: startRes.token };
    setTunnelId(startRes.tunnel_id);
    setLifecycle("connecting");

    // Pull remembered VNC password (vault read crosses the credential bridge once).
    let password = passwordOverride;
    if (password === undefined) {
      try {
        const saved = await vault.get(VNC_VAULT_PREFIX + serverId);
        if (saved) password = saved;
      } catch {}
    }
    if (seq !== startSeqRef.current) { await stopTunnelAndRfb(); return; }

    const target = containerRef.current;
    if (!target) { await stopTunnelAndRfb("Display target is not available"); return; }
    const url = `ws://127.0.0.1:${startRes.ws_port}/vnc/${startRes.token}`;
    const options: Record<string, unknown> = { wsProtocols: ["binary"] as string[] };
    if (password) options.credentials = { password };

    let rfb: InstanceType<typeof RFB>;
    try {
      // The constructor starts the connection (no separate connect()).
      rfb = new RFB(target, url, options as ConstructorParameters<typeof RFB>[2]);
    } catch (e) {
      await stopTunnelAndRfb(messageOf(e));
      return;
    }
    rfbRef.current = rfb;
    (rfb as unknown as { scaleViewport: boolean }).scaleViewport = fit;

    const onConnect = () => {
      if (seq !== startSeqRef.current) return;
      setLifecycle("connected");
      setLifecycleError(null);
      setCredDialogOpen(false);
      setCredTypes(null);
      setSecurityFailure(null);
      if (rfbRef.current) (rfbRef.current as unknown as { scaleViewport: boolean }).scaleViewport = fit;
    };
    const onDisconnect = (ev: Event) => {
      if (seq !== startSeqRef.current) return;
      const detail = (ev as CustomEvent<{ clean?: boolean }>).detail;
      const sf = securityFailureRef.current;
      const le = lifecycleErrorRef.current;
      rfbRef.current = null;
      const reason = sf || le || (!detail?.clean ? "The remote VNC session disconnected" : undefined);
      void stopTunnelAndRfb(reason).then(() => {
        if (!reason) {
          setLifecycle("stopped");
          setLifecycleError(null);
        }
      });
    };
    const onCredentialsRequired = (ev: Event) => {
      if (seq !== startSeqRef.current) return;
      const detail = (ev as CustomEvent<CredentialsRequiredDetail>).detail ?? {};
      const types: string[] = detail.types ?? ["password"];
      setCredTypes(types);
      setCredDialogMode("challenge");
      setLifecycle("credentials_required");
      setCredDialogOpen(true);
      setCredPassword("");
    };
    const onSecurityFailure = (ev: Event) => {
      if (seq !== startSeqRef.current) return;
      const detail = (ev as CustomEvent<SecurityFailureDetail>).detail ?? { status: 1 };
      const reason = detail.reason ? `: ${detail.reason}` : "";
      const msg = `Remote authentication failed (status ${detail.status})${reason}`;
      securityFailureRef.current = msg;
      lifecycleErrorRef.current = msg;
      setSecurityFailure(msg);
      setLifecycle("failed");
      setLifecycleError(msg);
      setCredDialogMode("retry");
      setCredTypes(["password"]);
      setCredPassword("");
      void (async () => {
        try { await vault.delete(VNC_VAULT_PREFIX + serverId); } catch {}
        await stopTunnelAndRfb();
        setLifecycle("failed");
        setLifecycleError(msg);
        setCredDialogOpen(true);
      })();
    };

    rfb.addEventListener("connect", onConnect as EventListener);
    rfb.addEventListener("disconnect", onDisconnect as EventListener);
    rfb.addEventListener("credentialsrequired", onCredentialsRequired as EventListener);
    rfb.addEventListener("securityfailure", onSecurityFailure as EventListener);

    // One-shot cleanup bindings (tied to this rfb instance).
    const detach = () => {
      try { rfb.removeEventListener("connect", onConnect as EventListener); } catch {}
      try { rfb.removeEventListener("disconnect", onDisconnect as EventListener); } catch {}
      try { rfb.removeEventListener("credentialsrequired", onCredentialsRequired as EventListener); } catch {}
      try { rfb.removeEventListener("securityfailure", onSecurityFailure as EventListener); } catch {}
    };
    // Patch rfb.disconnect to detach (avoid leaking listeners if reused).
    const origDisconnect = rfb.disconnect.bind(rfb);
    (rfb as unknown as { disconnect: () => void }).disconnect = () => { detach(); return origDisconnect(); };
  }, [serverId, display, derivedPort, useCustomPort, customPortRaw, fit, stopTunnelAndRfb]);

  useEffect(() => {
    if (!setupAutoConnect) return;
    setSetupAutoConnect(false);
    void start();
  }, [setupAutoConnect, start]);

  // Apply fit toggle to live RFB.
  useEffect(() => {
    const rfb = rfbRef.current;
    if (rfb) (rfb as unknown as { scaleViewport: boolean }).scaleViewport = fit;
  }, [fit]);

  // ── Submit or manage credentials
  const submitCredentials = useCallback(async () => {
    if (!credPassword) { setLifecycleError("Enter the VNC password"); return; }
    setCredBusy(true);
    try {
      if (credDialogMode === "manage") {
        await vault.set(VNC_VAULT_PREFIX + serverId, credPassword);
        setCredentialNotice("Saved VNC password replaced in Keychain");
        setCredDialogOpen(false);
        setCredPassword("");
        return;
      }
      if (credRemember) await vault.set(VNC_VAULT_PREFIX + serverId, credPassword);
      if (credDialogMode === "retry") {
        const retryPassword = credPassword;
        setCredDialogOpen(false);
        setCredPassword("");
        await start(retryPassword);
        return;
      }
      const rfb = rfbRef.current;
      if (!rfb) throw new Error("The VNC connection is no longer active");
      (rfb as unknown as { sendCredentials: (c: Record<string, string>) => void }).sendCredentials({ password: credPassword });
      setCredDialogOpen(false);
      setLifecycle("connecting");
      setLifecycleError(null);
      setCredPassword("");
    } catch (e) {
      setLifecycleError(messageOf(e));
    } finally {
      setCredBusy(false);
    }
  }, [credPassword, credRemember, credDialogMode, serverId, start]);

  const forgetSavedPassword = useCallback(async () => {
    setCredBusy(true);
    try {
      await vault.delete(VNC_VAULT_PREFIX + serverId);
      setCredentialNotice("Saved VNC password removed from Keychain");
      setCredDialogOpen(false);
      setCredPassword("");
    } catch (e) {
      setLifecycleError(messageOf(e));
    } finally {
      setCredBusy(false);
    }
  }, [serverId]);

  const openPasswordManager = useCallback(() => {
    setCredDialogMode("manage");
    setCredTypes(["password"]);
    setCredPassword("");
    setCredRemember(true);
    setLifecycleError(null);
    setCredDialogOpen(true);
  }, []);

  const closeCredentials = useCallback(() => {
    setCredDialogOpen(false);
    setCredPassword("");
    if (credDialogMode === "challenge") void disconnect();
  }, [credDialogMode, disconnect]);

  const statusLabel = useMemo(() => {
    switch (lifecycle) {
      case "idle": return "Idle";
      case "probing": return "Probing…";
      case "starting": return "Starting tunnel…";
      case "connecting": return "Connecting…";
      case "credentials_required": return "Password required";
      case "connected": return "Connected";
      case "failed": return "Failed";
      case "stopped": return "Stopped";
    }
  }, [lifecycle, lifecycleError]);

  const stageBusy = lifecycle === "starting" || lifecycle === "connecting";

  return (
    <div className="vnc" data-testid="vnc-tab" style={{ display: "flex", flexDirection: "column", minHeight: 0, flex: 1, gap: 0 }}>
      {/* Toolbar (compact, wraps cleanly; no overlapping controls) */}
      <div
        className="vnc-toolbar"
        data-testid="vnc-toolbar"
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: 8,
          padding: "10px 12px",
          borderBottom: "1px solid var(--border)",
          background: "var(--card)",
        }}
      >
        {/* Display presets */}
        <div role="group" aria-label="Display" style={{ display: "inline-flex", gap: 4, padding: 2, border: "1px solid var(--border)", borderRadius: 7, background: "var(--muted)" }}>
          {DISPLAY_PRESETS.map((preset) => (
            <button
              key={preset.label}
              data-testid={`vnc-display-${preset.label}`}
              aria-pressed={!useCustomPort && display === preset.value}
              onClick={() => { setUseCustomPort(false); setDisplay(preset.value); rememberDisplay(serverId, preset.value); setPortError(null); }}
              style={{
                height: 28, padding: "0 10px", borderRadius: 6, border: "1px solid transparent",
                background: (!useCustomPort && display === preset.value) ? "var(--card)" : "transparent",
                color: (!useCustomPort && display === preset.value) ? "var(--foreground)" : "var(--muted-foreground)",
                fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 11, fontWeight: 600, cursor: "pointer",
                boxShadow: (!useCustomPort && display === preset.value) ? "0 1px 3px oklch(0 0 0 / 0.08)" : "none",
              }}
            >
              {preset.label}
            </button>
          ))}
          <button
            data-testid="vnc-display-custom"
            aria-pressed={useCustomPort}
            onClick={() => setUseCustomPort(true)}
            style={{
              height: 28, padding: "0 10px", borderRadius: 6, border: "1px solid transparent",
              background: useCustomPort ? "var(--card)" : "transparent",
              color: useCustomPort ? "var(--foreground)" : "var(--muted-foreground)",
              fontSize: 11, fontWeight: 600, cursor: "pointer",
              boxShadow: useCustomPort ? "0 1px 3px oklch(0 0 0 / 0.08)" : "none",
            }}
          >
            Custom
          </button>
        </div>

        {/* Custom port input (validated) */}
        <label style={{ display: "inline-flex", alignItems: "center", gap: 6, minWidth: 0 }}>
          <span style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 10 }}>port</span>
          <input
            data-testid="vnc-custom-port"
            aria-label="Custom VNC port"
            inputMode="numeric"
            placeholder={useCustomPort ? "5900–5999" : String(portFromDisplay(display))}
            value={useCustomPort ? customPortRaw : String(portFromDisplay(display))}
            onChange={(e) => {
              if (!useCustomPort) setUseCustomPort(true);
              // keep raw string (typed); validate on start.
              const v = e.target.value.slice(0, CUSTOM_PORT_MIN_CHARS + 2);
              setCustomPortRaw(v);
              if (portError) setPortError(null);
            }}
            disabled={!useCustomPort}
            style={{
              width: 98, height: 30, padding: "0 8px", borderRadius: 6, border: `1px solid ${portError ? "var(--destructive)" : "var(--border)"}`,
              background: useCustomPort ? "var(--background)" : "var(--muted)", color: "var(--foreground)",
              fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 11, outline: "none",
            }}
          />
        </label>
        {portError && <span data-testid="vnc-port-error" style={{ color: "var(--destructive)", fontSize: 11 }}>{portError}</span>}

        {/* Connect / Disconnect */}
        {(lifecycle === "connected" || lifecycle === "connecting" || lifecycle === "starting" || lifecycle === "credentials_required") ? (
          <Button data-testid="vnc-disconnect" variant="outline" size="sm" onClick={() => void disconnect()}>
            <Unplug data-icon="inline-start" /> Disconnect
          </Button>
        ) : (
          <Button data-testid="vnc-connect" variant="default" size="sm" onClick={() => void start()} disabled={stageBusy}>
            <Monitor data-icon="inline-start" /> Connect
          </Button>
        )}
        <Button data-testid="vnc-password-manage" variant="outline" size="sm" onClick={openPasswordManager} disabled={stageBusy}>
          <KeyRound data-icon="inline-start" /> Password
        </Button>

        {/* Scale */}
        <div role="group" aria-label="Scale" style={{ display: "inline-flex", gap: 4, padding: 2, border: "1px solid var(--border)", borderRadius: 7, background: "var(--muted)" }}>
          <button
            data-testid="vnc-scale-fit"
            aria-pressed={fit}
            onClick={() => setFit(true)}
            style={{
              height: 28, padding: "0 10px", borderRadius: 6, border: "1px solid transparent",
              background: fit ? "var(--card)" : "transparent", color: fit ? "var(--foreground)" : "var(--muted-foreground)",
              fontSize: 11, fontWeight: 600, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5,
              boxShadow: fit ? "0 1px 3px oklch(0 0 0 / 0.08)" : "none",
            }}
          >
            <Maximize2 size={13} aria-hidden /> Fit
          </button>
          <button
            data-testid="vnc-scale-100"
            aria-pressed={!fit}
            onClick={() => setFit(false)}
            style={{
              height: 28, padding: "0 10px", borderRadius: 6, border: "1px solid transparent",
              background: !fit ? "var(--card)" : "transparent", color: !fit ? "var(--foreground)" : "var(--muted-foreground)",
              fontSize: 11, fontWeight: 600, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5,
              boxShadow: !fit ? "0 1px 3px oklch(0 0 0 / 0.08)" : "none",
            }}
          >
            <Minimize2 size={13} aria-hidden /> 100%
          </button>
        </div>

        <Button
          data-testid="vnc-ctrlaltdel"
          variant="ghost"
          size="sm"
          onClick={() => {
            const rfb = rfbRef.current;
            if (rfb) (rfb as unknown as { sendCtrlAltDel: () => void }).sendCtrlAltDel();
          }}
          disabled={lifecycle !== "connected"}
          title={lifecycle !== "connected" ? "Connect first" : "Send Ctrl+Alt+Del to the remote session"}
        >
          <Keyboard data-icon="inline-start" /> Ctrl+Alt+Del
        </Button>

        <label style={{ display: "inline-flex", alignItems: "center", gap: 6, minWidth: 0, flex: "1 1 160px", maxWidth: 260 }}>
          <input
            data-testid="vnc-clip-input"
            aria-label="Clipboard text to paste"
            placeholder="Clipboard text"
            value={clipText}
            onChange={(e) => setClipText(e.target.value.slice(0, CLIP_LIMIT))}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const rfb = rfbRef.current;
                if (rfb && clipText) {
                  (rfb as unknown as { clipboardPasteFrom: (t: string) => void }).clipboardPasteFrom(clipText);
                  setClipFeedback("Pasted to remote");
                  window.setTimeout(() => setClipFeedback(null), 1600);
                }
              }
            }}
            style={{
              flex: 1, minWidth: 0, height: 30, padding: "0 8px", borderRadius: 6, border: "1px solid var(--border)",
              background: "var(--background)", color: "var(--foreground)", fontSize: 11, outline: "none",
            }}
          />
          <Button
            data-testid="vnc-clip-paste"
            variant="outline"
            size="sm"
            onClick={() => {
              const rfb = rfbRef.current;
              if (!rfb) { setClipFeedback("Connect first"); window.setTimeout(() => setClipFeedback(null), 1600); return; }
              if (!clipText) { setClipFeedback("Enter clipboard text"); window.setTimeout(() => setClipFeedback(null), 1600); return; }
              (rfb as unknown as { clipboardPasteFrom: (t: string) => void }).clipboardPasteFrom(clipText);
              setClipFeedback("Pasted to remote");
              window.setTimeout(() => setClipFeedback(null), 1600);
            }}
          >
            <ClipboardPaste data-icon="inline-start" /> Paste
          </Button>
        </label>
        {clipFeedback && <span data-testid="vnc-clip-feedback" style={{ color: "var(--muted-foreground)", fontSize: 11 }}>{clipFeedback}</span>}

        {/* Status */}
        <span
          data-testid="vnc-status"
          className={`vnc-status vnc-status-${lifecycle}`}
          style={{
            marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6,
            color: lifecycle === "failed" ? "var(--destructive)" : lifecycle === "connected" ? "var(--primary)" : "var(--muted-foreground)",
            fontSize: 11, fontWeight: 600,
          }}
        >
          <span aria-hidden style={{ width: 6, height: 6, borderRadius: 999, background: "currentColor", opacity: lifecycle === "connecting" || lifecycle === "starting" ? 0.65 : 1 }} />
          {statusLabel}
        </span>
        {(pollState?.bytesUp != null || pollState?.bytesDown != null) && (
          <span data-testid="vnc-bytes" style={{ color: "var(--muted-foreground)", fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 10 }}>
            ↑ {bytesLabel(pollState?.bytesUp ?? 0)} · ↓ {bytesLabel(pollState?.bytesDown ?? 0)}
          </span>
        )}
      </div>

      {/* Probe + setup helper strip */}
      <div data-testid="vnc-probe-strip" style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", padding: "8px 12px", borderBottom: "1px solid var(--border)", background: "var(--muted)" }}>
        {probe.kind === "idle" || probe.kind === "loading" ? (
          <span style={{ color: "var(--muted-foreground)", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6 }}>
            <RefreshCw size={12} className={probe.kind === "loading" ? "spin" : undefined} aria-hidden /> Probing remote VNC…
          </span>
        ) : probe.kind === "error" ? (
          <>
            <span data-testid="vnc-probe-error" style={{ color: "var(--destructive)", fontSize: 11 }}>{probe.message}</span>
            <Button size="xs" variant="outline" onClick={() => void runProbe()}>Retry probe</Button>
          </>
        ) : (
          <>
            <span data-testid="vnc-probe-summary" style={{ fontSize: 11, color: "var(--foreground)" }}>
              VNC server: {probe.data.x11vnc && probe.data.tigervnc ? "x11vnc + TigerVNC" : probe.data.x11vnc ? "x11vnc" : probe.data.tigervnc ? "TigerVNC" : "not found"} · Desktop: {desktopProbeLabel(probe.data, display)} · listening: {probe.data.listening.length ? probe.data.listening.map((l) => `${l.port}${l.process ? ` (${l.process})` : ""}`).join(", ") : "none"}
            </span>
            {probe.data.setup_state === "installing" && (
              <span data-testid="vnc-setup-running" role="status" style={{ color: "var(--primary)", fontSize: 11, display: "inline-flex", alignItems: "center", gap: 6 }}>
                <RefreshCw size={12} className="spin" aria-hidden /> Package installation is still running
              </span>
            )}
            {probe.data.setup_state === "failed" && (
              <span data-testid="vnc-setup-failed-state" role="status" style={{ color: "var(--destructive)", fontSize: 11 }}>Last remote desktop setup failed</span>
            )}
            <Button size="xs" variant="ghost" onClick={() => void runProbe()}>Re-probe</Button>
            <Button data-testid="vnc-setup-cta" size="xs" variant="outline" onClick={() => void runSetupDry()} disabled={probe.data.setup_state === "installing"}>
              {probe.data.setup_state === "installing" ? "Installing packages" : probe.data.desktop_running ? "Configure server" : probe.data.window_manager_running ? "Repair desktop" : probe.data.desktop_installed && probe.data.desktop_name === "XFCE" ? "Start desktop" : "Set up desktop"}
            </Button>
          </>
        )}
      </div>

      {/* Setup plan states */}
      {setup.kind === "error" && (
        <div data-testid="vnc-setup-error" style={{ margin: "8px 12px 0", padding: "10px 12px", border: "1px solid color-mix(in oklch, var(--destructive) 18%, transparent)", borderRadius: 8, background: "color-mix(in oklch, var(--destructive) 7%, transparent)", color: "var(--destructive)", fontSize: 11 }}>
          {setup.message}
        </div>
      )}
      {setup.kind === "executed" && (
        <div data-testid="vnc-setup-executed" style={{ margin: "8px 12px 0", padding: "10px 12px", border: "1px solid var(--border)", borderRadius: 8, background: "var(--card)", color: "var(--foreground)", fontSize: 11, display: "flex", alignItems: "center", gap: 8 }}>
          {setup.data.desktop_action === "none" ? "VNC" : setup.data.desktop_name || "Desktop"} is configured on display :{display}; VNC remains bound to remote loopback.
        </div>
      )}
      {credentialNotice && (
        <div data-testid="vnc-credential-notice" role="status" style={{ margin: "8px 12px 0", padding: "10px 12px", border: "1px solid var(--border)", borderRadius: 8, background: "var(--card)", color: "var(--foreground)", fontSize: 11 }}>
          {credentialNotice}
        </div>
      )}
      {lifecycle === "failed" && lifecycleError && (
        <div data-testid="vnc-failed" style={{ margin: "8px 12px 0", padding: "10px 12px", border: "1px solid color-mix(in oklch, var(--destructive) 18%, transparent)", borderRadius: 8, background: "color-mix(in oklch, var(--destructive) 7%, transparent)", color: "var(--destructive)", fontSize: 11 }}>
          {lifecycleError}
        </div>
      )}

      {/* Workspace (noVNC target fills this; unframed inside primary content) */}
      <div
        data-testid="vnc-canvas"
        style={{
          flex: 1,
          minHeight: 420,
          // noVNC canvas fills target; keep remote canvas unframed.
          position: "relative",
          overflow: "hidden",
          background: "#0f1318",
          // When disconnected show a soft paper inset.
          display: "flex",
          alignItems: "stretch",
          justifyContent: "stretch",
        }}
      >
        <div ref={containerRef} className="vnc-rfb-target" data-testid="vnc-rfb-target" />
        <div
          data-vnc-placeholder
          data-testid="vnc-placeholder"
          style={{
            position: "absolute", zIndex: 1, inset: 0,
            display: lifecycle === "idle" || lifecycle === "stopped" || lifecycle === "failed" ? "flex" : "none",
            flexDirection: "column", alignItems: "center", justifyContent: "center",
            gap: 10, padding: 24, color: "var(--muted-foreground)", textAlign: "center", background: "var(--muted)",
          }}
        >
          <Monitor size={28} aria-hidden style={{ opacity: 0.7 }} />
          <div style={{ maxWidth: 520 }}>
            <p style={{ margin: 0, color: "var(--foreground)", fontSize: 13, fontWeight: 650 }}>Remote desktop over SSH</p>
            <p style={{ margin: "6px 0 0", fontSize: 11, lineHeight: 1.6 }}>
              Choose a display preset or a custom port, then Connect. Oars opens a loopback WebSocket tunnel to the remote VNC server and renders it locally. The tunnel closes with the SSH session.
            </p>
          </div>
          {pollState?.error && <span style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 10 }}>{pollState.error}</span>}
        </div>
        {(lifecycle === "starting" || lifecycle === "connecting") && (
          <div className="vnc-loading" data-testid="vnc-loading">
            <OarsLoadingState title={lifecycle === "starting" ? "Starting tunnel" : "Connecting display"} compact />
          </div>
        )}
      </div>

      {/* Credentials dialog */}
      {credDialogOpen && (
        <div className="oars-modal-overlay" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !credBusy) closeCredentials(); }}>
          <div
            data-testid="vnc-credentials-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="vnc-creds-title"
            className="oars-modal oars-modal-narrow"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="oars-modal-header">
              <div className="oars-modal-title-row">
                <span className="oars-modal-icon" aria-hidden><AlertTriangle size={15} /></span>
                <div>
                  <h2 id="vnc-creds-title">
                    {credDialogMode === "manage" ? "Saved VNC password" : credDialogMode === "retry" ? "Replace VNC password" : "VNC password required"}
                  </h2>
                  <p className="oars-modal-subtitle">
                    {credDialogMode === "manage"
                      ? "Replace or remove the password that Oars reads from the system Keychain."
                      : credDialogMode === "retry"
                        ? "The saved password was rejected and removed. Enter the current server password to reconnect."
                        : "The remote desktop requires a password. It is never stored in app configuration or logs."}
                  </p>
                </div>
                <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={closeCredentials} disabled={credBusy}><X size={14} /></Button>
              </div>
            </header>
            <div className="oars-modal-body" style={{ gap: 12 }}>
              {credDialogMode !== "manage" && credTypes && legacyVncAuthWarning(credTypes) && (
                <div data-testid="vnc-legacy-warning" style={{ padding: "10px 12px", border: "1px solid oklch(0.78 0.16 82 / 0.22)", borderRadius: 8, background: "color-mix(in oklch, oklch(0.78 0.16 82) 8%, transparent)", color: "var(--foreground)", fontSize: 11, lineHeight: 1.5 }}>
                  Legacy VNC Authentication is in use — only the first eight password characters are used to authenticate.
                </div>
              )}
              {lifecycleError && <div style={{ color: "var(--destructive)", fontSize: 11 }}>{lifecycleError}</div>}
              <label className="oars-field">
                <span className="oars-label">VNC password</span>
                <input
                  data-testid="vnc-password-input"
                  type="password"
                  autoFocus
                  value={credPassword}
                  onChange={(e) => setCredPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && !credBusy) void submitCredentials(); }}
                  placeholder="Enter VNC password"
                  style={{ height: 32, padding: "0 10px", border: "1px solid var(--border)", borderRadius: 7, background: "var(--background)", color: "var(--foreground)", fontSize: 12, outline: "none" }}
                />
              </label>
              {credDialogMode !== "manage" && (
                <label className="oars-check">
                  <input data-testid="vnc-remember" type="checkbox" checked={credRemember} onChange={(e) => setCredRemember(e.target.checked)} />
                  Remember in Keychain
                </label>
              )}
              <p style={{ margin: 0, color: "var(--muted-foreground)", fontSize: 10, lineHeight: 1.5 }}>
                Remembered passwords are stored as <code style={{ fontFamily: "var(--font-geist-mono, ui-monospace, monospace)", fontSize: 10 }}>vnc:{serverId}</code> in the system Keychain.
              </p>
            </div>
            <footer className="oars-modal-actions oars-modal-footer">
              {credDialogMode === "manage" && (
                <div className="oars-modal-actions-left">
                  <Button data-testid="vnc-password-forget" variant="ghost" onClick={() => void forgetSavedPassword()} disabled={credBusy}>Remove saved</Button>
                </div>
              )}
              <div className="oars-modal-actions-right">
                <Button variant="ghost" onClick={closeCredentials} disabled={credBusy}>Cancel</Button>
                <Button data-testid="vnc-password-submit" onClick={() => void submitCredentials()} disabled={credBusy || !credPassword}>
                  {credBusy ? "Working…" : credDialogMode === "manage" ? "Save password" : credRemember ? "Save and connect" : "Use once"}
                </Button>
              </div>
            </footer>
          </div>
        </div>
      )}

      {/* Setup approval modal (established Oars pattern) */}
      {setupApprovalOpen && setup.kind === "plan" && (
        <div className="oars-modal-overlay" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !setupBusy) setSetupApprovalOpen(false); }}>
          <div data-testid="vnc-setup-approval" role="dialog" aria-modal="true" aria-labelledby="vnc-setup-title" className="oars-modal oars-modal-narrow" onClick={(e) => e.stopPropagation()}>
            <header className="oars-modal-header">
              <div className="oars-modal-title-row">
                <span className="oars-modal-icon oars-modal-icon-danger" aria-hidden><AlertTriangle size={15} /></span>
                <div>
                  <h2 id="vnc-setup-title">
                    {setup.data.action === "manual"
                      ? "Manual remote desktop setup"
                      : setup.data.desktop_action === "install"
                        ? "Install XFCE desktop?"
                        : setup.data.desktop_action === "start"
                          ? "Start XFCE desktop?"
                          : setup.data.action === "configure" ? "Configure VNC server?" : "Install and configure VNC?"}
                  </h2>
                  <p className="oars-modal-subtitle">
                    {setup.data.action === "manual"
                      ? "Oars could not determine an install command for this server. Follow the guidance below."
                      : setup.data.desktop_action === "install"
                        ? "Oars will install a lightweight XFCE desktop, configure VNC, and start both on the selected display."
                        : setup.data.desktop_action === "start"
                          ? "Oars will start the installed XFCE desktop and configure VNC on the selected display."
                      : setup.data.action === "configure"
                        ? "Oars will set the server password and restart x11vnc on remote loopback."
                        : "Oars will install x11vnc, set its password, and start it on remote loopback. This action is audited."}
                  </p>
                </div>
                <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={() => setSetupApprovalOpen(false)} disabled={setupBusy}><X size={14} /></Button>
              </div>
            </header>
            <div className="oars-modal-body" style={{ gap: 12 }}>
              <label className="oars-check" style={{ alignItems: "flex-start", gap: 10 }}>
                <input
                  data-testid="vnc-setup-desktop"
                  type="checkbox"
                  checked={setupDesktop}
                  disabled={setupBusy}
                  onChange={(e) => void updateDesktopChoice(e.target.checked)}
                />
                <span style={{ display: "grid", gap: 2 }}>
                  <span style={{ color: "var(--foreground)", fontSize: 11, fontWeight: 600 }}>Install or start XFCE desktop</span>
                  <span style={{ color: "var(--muted-foreground)", fontSize: 10, lineHeight: 1.45 }}>
                    Recommended for headless servers. This adds desktop packages and runs them under the connected SSH account.
                  </span>
                </span>
              </label>
              {setup.data.action === "install" && (
                <div className="monitor-command-preview">
                  <span>Install command</span>
                  <code data-testid="vnc-setup-plan">{setup.data.plan}</code>
                </div>
              )}
              {setup.data.hint && setup.data.action !== "manual" && (
                <div className="monitor-command-preview">
                  <span>Secure command preview</span>
                  <code data-testid="vnc-setup-hint">{setup.data.hint}</code>
                </div>
              )}
              {setup.data.action === "manual" && setup.data.hint && (
                <p style={{ margin: 0, color: "var(--muted-foreground)", fontSize: 11, lineHeight: 1.6 }}>{setup.data.hint}</p>
              )}
              {setup.data.action !== "manual" && (
                <>
                  {setupPasswordError && <div className="oars-form-error" role="alert">{setupPasswordError}</div>}
                  <div className="vnc-password-grid">
                    <label className="oars-field">
                      <span className="oars-label">Server password</span>
                      <input
                        data-testid="vnc-setup-password"
                        type="password"
                        autoComplete="new-password"
                        value={setupPassword}
                        onChange={(e) => { setSetupPassword(e.target.value); setSetupPasswordError(null); }}
                        placeholder="Set VNC password"
                      />
                    </label>
                    <label className="oars-field">
                      <span className="oars-label">Confirm password</span>
                      <input
                        data-testid="vnc-setup-password-confirm"
                        type="password"
                        autoComplete="new-password"
                        value={setupPasswordConfirm}
                        onChange={(e) => { setSetupPasswordConfirm(e.target.value); setSetupPasswordError(null); }}
                        placeholder="Repeat VNC password"
                        onKeyDown={(e) => { if (e.key === "Enter" && !setupBusy) void executeSetup(); }}
                      />
                    </label>
                  </div>
                  <p style={{ margin: 0, color: "var(--muted-foreground)", fontSize: 10, lineHeight: 1.5 }}>
                    Oars sends the password through command input, creates a mode-0600 authentication file, and starts x11vnc with <code>-localhost -rfbauth</code>. The password is also saved in Keychain for this server.
                  </p>
                  {setupExecuting && (
                    <OarsLoadingState
                      compact
                      className="vnc-setup-progress"
                      title={setup.data.desktop_action === "install" ? "Installing XFCE desktop" : "Configuring remote desktop"}
                      detail={setup.data.desktop_action === "install" ? "Package installation can take up to 30 minutes and continues if Oars restarts." : `Oars is preparing display :${display}.`}
                    />
                  )}
                </>
              )}
            </div>
            <footer className="oars-modal-actions oars-modal-footer">
              <div className="oars-modal-actions-right">
                {setup.data.action !== "manual" && <Button variant="ghost" onClick={() => setSetupApprovalOpen(false)} disabled={setupBusy}>Cancel</Button>}
                {(setup.data.action === "install" || setup.data.action === "configure") && (
                  <Button data-testid="vnc-setup-run" onClick={() => void executeSetup()} disabled={setupBusy}>
                    {setupExecuting
                      ? setup.data.desktop_action === "install" ? "Installing desktop…" : "Configuring…"
                      : setupBusy
                        ? "Updating plan…"
                      : setup.data.desktop_action === "install"
                        ? "Install desktop"
                        : setup.data.desktop_action === "start"
                          ? "Start desktop"
                          : setup.data.action === "install" ? "Install and configure" : "Configure and restart"}
                  </Button>
                )}
                {setup.data.action === "manual" && (
                  <Button variant="outline" onClick={() => setSetupApprovalOpen(false)}>Close</Button>
                )}
              </div>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
