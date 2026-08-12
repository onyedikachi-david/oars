import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock3, CloudCog, Code2, ExternalLink, History, KeyRound, LoaderCircle, Pencil, Play, Plus, RefreshCw, Rocket, Server, ShieldCheck, Trash2, X, XCircle } from "lucide-react";
import { api, BridgeError, vault } from "./bridge";
import { Button } from "./components/ui/button";
import { useModalFocus } from "./components/useModalFocus";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { approvalIds, appendDeployOutput, bulkImportEnv, cursorsFromSteps, mergeImportedEnv, type BulkImportResult } from "./deploy-state";
import type { DeployApp, DeployAppInput, DeployEnvVar, DeployHistoryRecord, DeployPollResult, DeployPreflight, DeployStep } from "./types";

type EditorState = DeployAppInput & { id?: string };
type DeleteState = { app: DeployApp; busy: boolean; error: string | null };

const terminalStatuses = new Set(["done", "failed", "canceled", "interrupted"]);
const account = (appId: string, name: string) => `deploy:${appId}:${name}`;
const messageOf = (error: unknown) => error instanceof BridgeError ? error.message : error instanceof Error ? error.message : String(error);
const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

async function waitForSshCommand(serverId: string, channel: number): Promise<string> {
  let cursor = 0;
  let output = "";
  let missing = 0;
  try {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const result = await api.ssh.poll(serverId, [{ channel, cursor }], false);
      const current = result.channels.find((entry) => entry.id === channel);
      if (!current) {
        missing += 1;
        if (missing >= 8) throw new Error("The SSH command output was not available.");
        await wait(250);
        continue;
      }
      missing = 0;
      output += current.data;
      cursor = current.cursor;
      if (current.eof) {
        if (current.exit !== 0) {
          const detail = output.trim();
          throw new Error(detail || "The SSH command failed.");
        }
        return output;
      }
      await wait(250);
    }
    throw new Error("The SSH command timed out.");
  } finally {
    void api.ssh.closeChannel(serverId, channel).catch(() => undefined);
  }
}

function cloneApp(app: DeployApp): EditorState {
  return { ...app, repo: { ...app.repo }, runtime: { ...app.runtime }, env_vars: app.env_vars.map((row) => ({ ...row })), domains: [...app.domains] };
}

function emptyEditor(serverId: string): EditorState {
  return {
    server_id: serverId,
    name: "",
    environment: "production",
    folder: "",
    repo: { url: "", transport: "https", branch: "main" },
    runtime: { node_version: "24", type: "next", package_manager: "auto", install: "", build: "npm run build", entry: "node_modules/next/dist/bin/next", args: "start", start_command: "", build_folder: ".next" },
    env_vars: [], domains: [], ssl: false, email: "", app_port: 3000,
  };
}

function runLabel(status: string) {
  if (status === "done") return "Live";
  if (status === "running" || status === "queued") return "Deploying";
  if (status === "cancel_requested") return "Cancel requested";
  if (status === "failed" || status === "interrupted") return "Needs attention";
  if (status === "canceled") return "Canceled";
  return "Not deployed";
}

export function DeployTab({ serverId }: { serverId: string }) {
  const [apps, setApps] = useState<DeployApp[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [history, setHistory] = useState<DeployHistoryRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [editorOriginal, setEditorOriginal] = useState<DeployApp | null>(null);
  const [editorBusy, setEditorBusy] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [bulkPreview, setBulkPreview] = useState<BulkImportResult | null>(null);
  const [deleteState, setDeleteState] = useState<DeleteState | null>(null);
  const [preflight, setPreflight] = useState<DeployPreflight | null>(null);
  const [preflightBusy, setPreflightBusy] = useState(false);
  const [repoActionBusy, setRepoActionBusy] = useState(false);
  const [deployPublicKey, setDeployPublicKey] = useState("");
  const [approvals, setApprovals] = useState<Record<string, boolean>>({});
  const [secretInputs, setSecretInputs] = useState<Record<string, string>>({});
  const [runId, setRunId] = useState<number | null>(null);
  const [runAppId, setRunAppId] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState("");
  const [steps, setSteps] = useState<DeployStep[]>([]);
  const [outputs, setOutputs] = useState<Record<string, string>>({});
  const [gaps, setGaps] = useState<Record<string, boolean>>({});
  const pollGeneration = useRef(0);
  const preflightGeneration = useRef(0);
  const historyGeneration = useRef(0);
  const preflightIdRef = useRef<number | null>(null);
  const cursorsRef = useRef<Record<string, number>>({});
  const outputRef = useRef<Record<string, string>>({});
  const gapsRef = useRef<Record<string, boolean>>({});

  const selected = useMemo(() => apps.find((app) => app.id === selectedId) ?? apps[0] ?? null, [apps, selectedId]);
  const latest = history[0] ?? null;
  const publicUrl = selected?.domains[0] ? `${selected.ssl ? "https" : "http"}://${selected.domains[0]}` : null;
  const activeRun = runId != null && runAppId === selected?.id;
  const displayStatus = activeRun && !terminalStatuses.has(runStatus) ? runStatus : latest?.status ?? "idle";

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.deploy.list(serverId);
      setApps(response.apps);
      setSelectedId((current) => response.apps.some((app) => app.id === current) ? current : response.apps[0]?.id ?? null);
      setError(null);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setLoading(false);
      setHasLoaded(true);
    }
  }, [serverId]);

  const loadHistory = useCallback(async (appId: string) => {
    const generation = ++historyGeneration.current;
    try {
      const response = await api.deploy.history(serverId, appId, 10);
      if (generation === historyGeneration.current) setHistory(response.runs);
    } catch (cause) {
      if (generation === historyGeneration.current) setError(messageOf(cause));
    }
  }, [serverId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { setHistory([]); setDeployPublicKey(""); if (selected) void loadHistory(selected.id); }, [selected?.id, loadHistory]);
  useEffect(() => {
    type PaletteWindow = Window & {
      __oarsDeployPalette?: Array<{ id: string; name: string; server_id: string }>;
      __oarsRequestedDeployApp?: { appId: string; serverId: string };
    };
    const target = window as PaletteWindow;
    target.__oarsDeployPalette = [
      ...(target.__oarsDeployPalette ?? []).filter((app) => app.server_id !== serverId),
      ...apps.map(({ id, name, server_id }) => ({ id, name, server_id })),
    ];
    const selectRequested = (event: Event) => {
      const detail = (event as CustomEvent<{ appId: string; serverId: string }>).detail;
      if (detail?.serverId === serverId && apps.some((app) => app.id === detail.appId)) setSelectedId(detail.appId);
    };
    window.addEventListener("oars:select-deploy-app", selectRequested);
    const pending = target.__oarsRequestedDeployApp;
    if (pending?.serverId === serverId && apps.some((app) => app.id === pending.appId)) {
      setSelectedId(pending.appId);
      delete target.__oarsRequestedDeployApp;
    }
    return () => {
      window.removeEventListener("oars:select-deploy-app", selectRequested);
      target.__oarsDeployPalette = (target.__oarsDeployPalette ?? []).filter((app) => app.server_id !== serverId);
    };
  }, [apps, serverId]);
  useEffect(() => () => {
    pollGeneration.current += 1;
    preflightGeneration.current += 1;
    historyGeneration.current += 1;
    const preflightId = preflightIdRef.current;
    preflightIdRef.current = null;
    if (preflightId != null) void api.deploy.preflightCancel(preflightId).catch(() => undefined);
  }, []);
  useEffect(() => {
    preflightGeneration.current += 1;
    const preflightId = preflightIdRef.current;
    preflightIdRef.current = null;
    if (preflightId != null) void api.deploy.preflightCancel(preflightId).catch(() => undefined);
    setPreflightBusy(false); setPreflight(null); setApprovals({}); setSecretInputs({});
  }, [selected?.id]);

  const startPreflight = async () => {
    if (!selected) return;
    const generation = ++preflightGeneration.current;
    setPreflightBusy(true); setPreflight(null); setApprovals({}); setError(null);
    try {
      const previous = preflightIdRef.current;
      preflightIdRef.current = null;
      if (previous != null) await api.deploy.preflightCancel(previous).catch(() => undefined);
      if (generation !== preflightGeneration.current) return;
      let current = (await api.deploy.preflight(serverId, selected.id)).preflight;
      if (generation !== preflightGeneration.current) return;
      preflightIdRef.current = current.id;
      setPreflight(current);
      while (current.status === "gathering") {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        if (generation !== preflightGeneration.current) return;
        current = (await api.deploy.preflightPoll(current.id)).preflight;
        setPreflight(current);
      }
    } catch (cause) {
      if (generation === preflightGeneration.current) setError(messageOf(cause));
    } finally {
      if (generation === preflightGeneration.current) setPreflightBusy(false);
    }
  };

  const cancelPreflight = async () => {
    const currentId = preflightIdRef.current ?? preflight?.id ?? null;
    preflightIdRef.current = null;
    preflightGeneration.current += 1;
    setPreflightBusy(false); setPreflight(null); setApprovals({});
    if (currentId != null) await api.deploy.preflightCancel(currentId).catch(() => undefined);
  };

  const createDeployKey = async () => {
    if (!selected) return;
    setRepoActionBusy(true); setError(null);
    try {
      const response = await api.deploy.keyGenerate(serverId, selected.id);
      const output = await waitForSshCommand(serverId, response.channel);
      const marker = output.indexOf("@public\n");
      const publicKey = marker >= 0 ? output.slice(marker + 8).trim().split("\n", 1)[0] : "";
      if (!publicKey.startsWith("ssh-ed25519 ")) throw new Error("The deploy public key response was invalid.");
      setDeployPublicKey(publicKey);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setRepoActionBusy(false);
    }
  };

  const trustGitHost = async () => {
    if (!preflight || !approvals["git-host-key"]) return;
    setRepoActionBusy(true); setError(null);
    try {
      const response = await api.deploy.hostTrust(preflight.id);
      await waitForSshCommand(serverId, response.channel);
      preflightIdRef.current = null;
      setPreflight(null); setApprovals({});
      await startPreflight();
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setRepoActionBusy(false);
    }
  };

  const openEditor = (app?: DeployApp) => {
    setEditor(app ? cloneApp(app) : emptyEditor(serverId));
    setEditorOriginal(app ?? null); setBulkText(""); setBulkPreview(null); setError(null);
  };

  const saveEditor = async () => {
    if (!editor) return;
    if (!editor.name.trim() || !editor.folder.startsWith("/") || !editor.repo.url.trim()) {
      setError("Enter a name, an absolute server folder, and a repository URL.");
      return;
    }
    setEditorBusy(true); setError(null);
    const before = editorOriginal ? cloneApp(editorOriginal) : null;
    const secretSnapshot = new Map<string, string>();
    const touched: string[] = [];
    const removed: string[] = [];
    try {
      if (before?.id) {
        for (const row of before.env_vars.filter((item) => item.secret && item.has_value)) {
          const value = await vault.deployTransientGet(account(before.id, row.name));
          if (value == null) throw new Error(`The stored value for ${row.name} could not be read. No changes were saved.`);
          secretSnapshot.set(row.name, value);
        }
      }
      const secretValues = editor.env_vars.filter((row) => row.secret && row.value.length > 0).map((row) => ({ name: row.name, value: row.value }));
      const payload: DeployAppInput = {
        ...editor,
        name: editor.name.trim(), folder: editor.folder.trim(),
        repo: { ...editor.repo, url: editor.repo.url.trim(), branch: editor.repo.branch.trim() || "main" },
        env_vars: editor.env_vars.map((row) => ({ name: row.name, secret: row.secret, value: row.secret ? "" : row.value, has_value: row.secret ? row.has_value : row.value.length > 0 })),
        domains: editor.domains.map((domain) => domain.trim()).filter(Boolean),
      };
      let saved = (await api.deploy.save(payload)).app;
      try {
        for (const secret of secretValues) {
          await vault.set(account(saved.id, secret.name), secret.value);
          await vault.transientForget(account(saved.id, secret.name));
          touched.push(secret.name);
        }
        const keep = new Set(editor.env_vars.filter((row) => row.secret).map((row) => row.name));
        for (const name of (before?.env_vars ?? []).filter((row) => row.secret && row.has_value && !keep.has(row.name)).map((row) => row.name)) {
          await vault.delete(account(saved.id, name));
          removed.push(name);
        }
        if (touched.length) saved = (await api.deploy.secretPresence(saved.id, touched, true)).app;
      } catch (cause) {
        if (before?.id) {
          await api.deploy.save(before);
          const restoredPresent: string[] = [];
          for (const name of new Set([...secretSnapshot.keys(), ...touched, ...removed])) {
            const old = secretSnapshot.get(name);
            if (old == null) await vault.delete(account(before.id, name));
            else {
              await vault.set(account(before.id, name), old);
              restoredPresent.push(name);
            }
          }
          if (restoredPresent.length) await api.deploy.secretPresence(before.id, restoredPresent, true);
        } else {
          for (const name of touched) await vault.delete(account(saved.id, name)).catch(() => undefined);
          await api.deploy.remove(serverId, saved.id);
        }
        throw cause;
      }
      for (const name of secretSnapshot.keys()) await vault.transientForget(account(saved.id, name));
      setEditor(null); setEditorOriginal(null); setBulkPreview(null); setBulkText("");
      await load(); setSelectedId(saved.id);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setEditorBusy(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteState) return;
    const app = deleteState.app;
    setDeleteState({ ...deleteState, busy: true, error: null });
    const snapshots = new Map<string, string>();
    const removed: string[] = [];
    try {
      for (const row of app.env_vars.filter((item) => item.secret && item.has_value)) {
        const value = await vault.deployTransientGet(account(app.id, row.name));
        if (value == null) throw new Error(`The stored value for ${row.name} could not be read.`);
        snapshots.set(row.name, value);
      }
      for (const name of snapshots.keys()) { await vault.delete(account(app.id, name)); removed.push(name); }
      await api.deploy.remove(serverId, app.id);
      setDeleteState(null); await load();
    } catch (cause) {
      for (const name of removed) {
        const value = snapshots.get(name);
        if (value != null) await vault.set(account(app.id, name), value).catch(() => undefined);
      }
      setDeleteState({ app, busy: false, error: `${messageOf(cause)} The app was not deleted.` });
    }
  };

  const startRun = async () => {
    if (!selected || !preflight || preflight.status !== "ready") return;
    const required = approvalIds(preflight);
    if (required.some((id) => !approvals[id])) { setError("Approve every required change before deployment."); return; }
    const values: Array<{ name: string; value: string }> = [];
    try {
      for (const row of selected.env_vars.filter((item) => item.secret)) {
        const typed = secretInputs[row.name];
        const value = typed || await vault.deployTransientGet(account(selected.id, row.name));
        if (!value) throw new Error(`Enter or store a value for ${row.name}.`);
        values.push({ name: row.name, value });
        await vault.transientForget(account(selected.id, row.name));
      }
      const response = await api.deploy.run({ preflight_id: preflight.id, approvals: required, secret_values: values });
      preflightIdRef.current = null;
      cursorsRef.current = {}; outputRef.current = {}; gapsRef.current = {};
      setOutputs({}); setGaps({}); setSteps([]); setRunStatus("queued"); setRunAppId(selected.id); setRunId(response.run_id); setPreflight(null); setSecretInputs({});
    } catch (cause) { setError(messageOf(cause)); }
  };

  const resetRun = () => {
    pollGeneration.current += 1;
    setRunId(null); setRunAppId(null); setRunStatus(""); setSteps([]); setOutputs({}); setGaps({});
    cursorsRef.current = {}; outputRef.current = {}; gapsRef.current = {};
  };

  const selectApp = (appId: string) => {
    if (runId != null && runAppId !== appId && !terminalStatuses.has(runStatus)) {
      setError("A deployment is still active. Wait for it to finish or request cancellation before opening another application.");
      return;
    }
    if (runId != null && runAppId !== appId) resetRun();
    setSelectedId(appId);
  };

  const requestRunCancel = async () => {
    if (runId == null) return;
    try {
      await api.deploy.cancel(runId);
      setRunStatus("cancel_requested");
      setError(null);
    } catch (cause) {
      setError(messageOf(cause));
    }
  };

  useEffect(() => {
    if (runId == null) return;
    const generation = ++pollGeneration.current;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result: DeployPollResult = await api.deploy.poll(runId, cursorsRef.current);
        if (generation !== pollGeneration.current) return;
        setRunStatus(result.status); setSteps(result.steps);
        cursorsRef.current = { ...cursorsRef.current, ...cursorsFromSteps(result.steps) };
        const nextOutputs = { ...outputRef.current };
        const nextGaps = { ...gapsRef.current };
        for (const step of result.steps) {
          const appended = appendDeployOutput(nextOutputs[step.id] ?? "", step.data, step.gap, nextGaps[step.id] ?? false);
          nextOutputs[step.id] = appended.text; nextGaps[step.id] = appended.gapNoted;
        }
        outputRef.current = nextOutputs; gapsRef.current = nextGaps; setOutputs(nextOutputs); setGaps(nextGaps);
        if (result.done) { if (runAppId) void loadHistory(runAppId); return; }
        timer = window.setTimeout(poll, 800);
      } catch (cause) {
        if (generation !== pollGeneration.current) return;
        setError(`${messageOf(cause)} Retrying deployment status…`);
        timer = window.setTimeout(poll, 1600);
      }
    };
    void poll();
    return () => { pollGeneration.current += 1; if (timer) window.clearTimeout(timer); };
  }, [runId, runAppId, loadHistory]);

  if (loading && !hasLoaded) return <OarsLoadingState title="Loading deployments" detail="Oars is reading the applications configured for this server." />;

  return (
    <section className="deploy-workspace" aria-label="Deployments">
      <aside className="deploy-sidebar">
        <div className="deploy-sidebar-heading">
          <div><span className="deploy-kicker">Applications</span><strong>{apps.length} configured</strong></div>
          <Button size="icon-sm" aria-label="New application" onClick={() => openEditor()}><Plus /></Button>
        </div>
        {loading && <OarsRefreshStatus label="Updating applications" />}
        <div className="deploy-app-list" role="listbox" aria-label="Applications">
          {apps.map((app) => {
            const active = selected?.id === app.id;
            return <button key={app.id} type="button" role="option" aria-selected={active} className={`deploy-app-row${active ? " is-selected" : ""}`} onClick={() => selectApp(app.id)}>
              <span className="deploy-app-mark"><Server /></span>
              <span className="deploy-app-copy"><strong>{app.name}</strong><small>{app.environment} · {app.repo.branch}</small><small className="deploy-app-folder">{app.folder}</small></span>
              <span className="deploy-app-chevron">›</span>
            </button>;
          })}
          {!apps.length && <div className="deploy-empty-small"><CloudCog /><strong>No applications yet</strong><span>Add a repository to prepare its first deployment.</span></div>}
        </div>
        <Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw />Refresh</Button>
      </aside>

      <div className="deploy-main">
        {error && <div className="deploy-alert is-error" role="alert"><XCircle /><span>{error}</span><Button size="icon-xs" variant="ghost" aria-label="Dismiss error" onClick={() => setError(null)}><X /></Button></div>}
        {!selected ? <div className="deploy-empty"><Rocket /><h2>Prepare your first application</h2><p>Save a repository, review live server checks, and deploy the exact approved plan.</p><Button onClick={() => openEditor()}><Plus />New application</Button></div> : <>
          <header className="deploy-hero">
            <div><span className="deploy-kicker">{selected.environment} application</span><h2>{selected.name}</h2><p><Code2 />{selected.repo.url} <span>·</span> {selected.repo.branch}</p></div>
            <div className="deploy-hero-actions"><Button variant="outline" onClick={() => openEditor(selected)}><Pencil />Edit</Button><Button variant="destructive" onClick={() => setDeleteState({ app: selected, busy: false, error: null })}><Trash2 />Delete</Button></div>
          </header>

          <div className="deploy-summary-strip">
            <div><span>Status</span><strong className={`deploy-status status-${displayStatus}`}><i />{runLabel(displayStatus)}</strong></div>
            <div><span>Runtime</span><strong>{selected.runtime.type} · Node {selected.runtime.node_version}</strong></div>
            <div><span>Destination</span><strong>{selected.folder}</strong></div>
            <div><span>Last deploy</span><strong>{latest ? new Date(latest.started_at_ms).toLocaleString() : "Never"}</strong></div>
          </div>

          {latest?.status === "done" && <section className="deploy-live-card"><div className="deploy-live-icon"><CheckCircle2 /></div><div><span>Live</span><strong>{publicUrl ?? "Deployment completed"}</strong><p>Commit {latest.commit?.slice(0, 10) || "recorded"} is running on this server.</p></div><div>{publicUrl && <Button variant="outline" onClick={() => window.open(publicUrl, "_blank", "noopener,noreferrer")}><ExternalLink />Open site</Button>}<Button variant="outline" onClick={() => document.getElementById("deploy-run-history")?.scrollIntoView({ behavior: "smooth" })}><History />View logs</Button></div></section>}

          <section className="deploy-panel">
            <div className="deploy-panel-heading"><div><span className="deploy-kicker">Safety review</span><h3>Preflight and deployment plan</h3><p>Oars reads the server first, then freezes the exact commands and file changes for approval.</p></div><Button onClick={() => void startPreflight()} disabled={preflightBusy || (runId != null && !terminalStatuses.has(runStatus))}>{preflightBusy ? <><LoaderCircle className="is-spinning" />Checking server</> : <><ShieldCheck />{preflight ? "Check again" : "Run preflight"}</>}</Button></div>
            {!preflight && <div className="deploy-preflight-placeholder"><ShieldCheck /><div><strong>No reviewed plan yet</strong><span>Preflight does not change the application or services. For a fresh repository, it removes its temporary inspection checkout when the check ends.</span></div></div>}
            {preflight && <div className="deploy-preflight" aria-live="polite">
              <div className="deploy-preflight-state"><strong>{preflight.status === "gathering" ? "Reading server state" : preflight.status === "ready" ? "Ready for approval" : preflight.status === "blocked" ? "Deployment blocked" : "Preflight failed"}</strong><span>{preflight.facts.os || "Waiting for facts"} · {preflight.facts.arch || "—"} · {preflight.facts.privilege || "—"}{preflight.facts.ports ? ` · ${preflight.facts.ports}` : ""}</span><Button size="sm" variant="ghost" onClick={() => void cancelPreflight()}>Clear review</Button></div>
              {(preflight.error || preflight.blockers.length > 0) && <div className="deploy-issues is-blocked"><AlertTriangle /><div><strong>{preflight.error ? "Preflight could not finish" : "Resolve before deployment"}</strong>{preflight.error && <p>{preflight.error}</p>}{preflight.blockers.map((issue) => <p key={issue.id}>{issue.message}</p>)}</div></div>}
              {preflight.blockers.some((issue) => issue.id === "missing_deploy_key") && <div className="deploy-recovery-card"><KeyRound /><div><strong>Create this application’s deploy key</strong><p>Add the public key to the repository with read access, then run preflight again.</p></div><Button variant="outline" disabled={repoActionBusy} onClick={() => void createDeployKey()}>{repoActionBusy ? <LoaderCircle className="is-spinning" /> : <KeyRound />}Create key</Button></div>}
              {deployPublicKey && <div className="deploy-public-key"><div><strong>Repository deploy key</strong><p>Add this public key to the repository with read access. Oars keeps the private key on this server.</p></div><pre>{deployPublicKey}</pre><Button size="sm" variant="outline" onClick={() => void navigator.clipboard.writeText(deployPublicKey)}>Copy public key</Button></div>}
              {preflight.warnings.length > 0 && <div className="deploy-issues"><AlertTriangle /><div><strong>Review these limits</strong>{preflight.warnings.map((issue) => <p key={issue.id}>{issue.message}</p>)}</div></div>}
              {preflight.facts.git_host_fingerprints && <details className="deploy-trust-details"><summary><KeyRound />Git host fingerprints</summary><p>Compare these SHA-256 fingerprints with a trusted source for the Git host before you approve first use.</p><pre>{preflight.facts.git_host_fingerprints}</pre></details>}
              <div className="deploy-plan-list">{preflight.steps.map((step, index) => <details key={step.id} className="deploy-plan-step"><summary><span>{index + 1}</span><div><strong>{step.label}</strong><small>{step.skipped ? "Skipped" : step.mutation}</small></div><code>{step.files[0]?.path ?? "remote command"}</code></summary>{!step.skipped && <div><pre>{step.command}</pre>{step.guards.map((guard) => <p key={guard}><ShieldCheck />{guard}</p>)}{step.rollback && <p><RefreshCw />{step.rollback}</p>}</div>}</details>)}</div>
              {(preflight.configs.env || preflight.configs.pm2 || preflight.configs.nginx) && <div className="deploy-config-previews"><strong>Reviewed file previews</strong>{([['Environment file', preflight.configs.env], ['PM2 ecosystem', preflight.configs.pm2], ['Nginx site', preflight.configs.nginx]] as const).filter(([, value]) => value).map(([label, value]) => <details key={label}><summary>{label}</summary><pre>{value}</pre></details>)}</div>}
              {preflight.approvals.length > 0 && <div className="deploy-approvals"><strong>Required approvals</strong>{preflight.approvals.map((approval) => <label key={approval.id}><input type="checkbox" checked={approvals[approval.id] ?? false} onChange={(event) => setApprovals((current) => ({ ...current, [approval.id]: event.target.checked }))} /><span><b>{approval.label}</b><small>{approval.detail}</small></span></label>)}</div>}
              {preflight.approvals.some((approval) => approval.id === "git-host-key") && <div className="deploy-host-trust-action"><p>This writes only the approved key to this application’s private known-hosts file. Preflight then checks repository access again.</p><Button variant="outline" disabled={repoActionBusy || !approvals["git-host-key"]} onClick={() => void trustGitHost()}>{repoActionBusy ? <LoaderCircle className="is-spinning" /> : <ShieldCheck />}Trust host and check again</Button></div>}
              {selected.env_vars.some((row) => row.secret) && <div className="deploy-secret-grid"><div><KeyRound /><span><strong>Deployment secrets</strong><small>Use stored Keychain values or enter a value for this run.</small></span></div>{selected.env_vars.filter((row) => row.secret).map((row) => <label key={row.name} htmlFor={`deploy-secret-${row.name}`}><span>{row.name}</span><input id={`deploy-secret-${row.name}`} type="password" autoComplete="off" placeholder={row.has_value ? "Stored — leave blank to reuse" : "Required value"} value={secretInputs[row.name] ?? ""} onChange={(event) => setSecretInputs((current) => ({ ...current, [row.name]: event.target.value }))} /></label>)}</div>}
              <div className="deploy-commit-row"><p>{preflight.commit ? `Frozen commit ${preflight.commit.slice(0, 12)}` : "The repository commit must be resolved before deployment."}</p><Button onClick={() => void startRun()} disabled={preflight.status !== "ready" || preflight.blockers.length > 0 || approvalIds(preflight).some((id) => !approvals[id])}><Play />Deploy reviewed plan</Button></div>
            </div>}
          </section>

          {activeRun && <section className="deploy-panel deploy-run" aria-live="polite"><div className="deploy-panel-heading"><div><span className="deploy-kicker">Run #{runId}</span><h3>{runLabel(runStatus)}</h3></div>{!terminalStatuses.has(runStatus) && <Button variant="destructive" onClick={() => void requestRunCancel()}><X />Request cancel</Button>}</div><div className="deploy-run-steps">{steps.map((step) => <div key={step.id} className={`deploy-run-step state-${step.state}`}><span className="deploy-run-state">{step.state === "success" ? <CheckCircle2 /> : step.state === "failed" ? <XCircle /> : step.state === "running" ? <LoaderCircle className="is-spinning" /> : <Clock3 />}</span><div><strong>{step.label}</strong><small>{step.error || step.state}{step.exit != null ? ` · exit ${step.exit}` : ""}</small>{gaps[step.id] && <p className="deploy-gap">Earlier output was dropped before this view read it.</p>}{outputs[step.id] && <pre>{outputs[step.id]}</pre>}</div></div>)}</div>{terminalStatuses.has(runStatus) && <Button variant="outline" onClick={resetRun}>Close run</Button>}</section>}

          <section id="deploy-run-history" className="deploy-panel"><div className="deploy-panel-heading"><div><span className="deploy-kicker">History</span><h3>Recent deployments</h3></div><Button size="sm" variant="ghost" onClick={() => void loadHistory(selected.id)}><RefreshCw />Refresh</Button></div>{history.length ? <div className="deploy-history">{history.map((entry) => <details key={entry.id}><summary><span className={`deploy-history-state status-${entry.status}`}><i />{runLabel(entry.status)}</span><strong>{entry.action}</strong><time>{new Date(entry.started_at_ms).toLocaleString()}</time><code>{entry.commit?.slice(0, 10) || "—"}</code></summary>{entry.output && <pre>{entry.output}</pre>}</details>)}</div> : <div className="deploy-preflight-placeholder"><History /><div><strong>No deployments yet</strong><span>The first completed run will appear here.</span></div></div>}</section>
        </>}
      </div>

      {editor && <DeployEditor editor={editor} setEditor={setEditor} busy={editorBusy} error={error} bulkText={bulkText} setBulkText={setBulkText} bulkPreview={bulkPreview} onPreview={() => setBulkPreview(bulkImportEnv(bulkText, editor.env_vars))} onApplyPreview={() => { if (!bulkPreview) return; setEditor({ ...editor, env_vars: mergeImportedEnv(editor.env_vars, bulkPreview.rows) }); setBulkText(""); setBulkPreview(null); }} onCancel={() => { if (!editorBusy) { setEditor(null); setEditorOriginal(null); setBulkPreview(null); } }} onSave={() => void saveEditor()} />}
      {deleteState && <DeleteDialog state={deleteState} onCancel={() => { if (!deleteState.busy) setDeleteState(null); }} onConfirm={() => void confirmDelete()} />}
    </section>
  );
}

function DeployEditor({ editor, setEditor, busy, error, bulkText, setBulkText, bulkPreview, onPreview, onApplyPreview, onCancel, onSave }: { editor: EditorState; setEditor: (value: EditorState) => void; busy: boolean; error: string | null; bulkText: string; setBulkText: (value: string) => void; bulkPreview: BulkImportResult | null; onPreview: () => void; onApplyPreview: () => void; onCancel: () => void; onSave: () => void }) {
  const dialogRef = useModalFocus(onCancel, "#deploy-app-name", !busy);
  const updateRuntime = (patch: Partial<EditorState["runtime"]>) => setEditor({ ...editor, runtime: { ...editor.runtime, ...patch } });
  const changeRuntimeType = (type: EditorState["runtime"]["type"]) => {
    const defaults = type === "next"
      ? { build: "npm run build", entry: "node_modules/next/dist/bin/next", args: "start", start_command: "", build_folder: ".next" }
      : type === "node"
        ? { build: "", entry: "server.js", args: "", start_command: "", build_folder: "" }
        : type === "react"
          ? { build: "npm run build", entry: "", args: "", start_command: "", build_folder: "dist" }
          : { build: "", entry: "", args: "", start_command: "", build_folder: "dist" };
    updateRuntime({ type, ...defaults });
  };
  const updateRepo = (patch: Partial<EditorState["repo"]>) => setEditor({ ...editor, repo: { ...editor.repo, ...patch } });
  const updateEnv = (index: number, patch: Partial<DeployEnvVar>) => setEditor({ ...editor, env_vars: editor.env_vars.map((row, rowIndex) => rowIndex === index ? { ...row, ...patch } : row) });
  return <div className="oars-modal-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}><div ref={dialogRef} className="oars-modal deploy-editor-modal" role="dialog" aria-modal="true" aria-labelledby="deploy-editor-title" aria-describedby="deploy-editor-desc"><header className="oars-modal-header"><div className="oars-modal-title-row"><span className="oars-modal-icon"><Rocket /></span><div><h2 id="deploy-editor-title">{editor.id ? "Edit application" : "New application"}</h2><p id="deploy-editor-desc" className="oars-modal-subtitle">Application metadata stays local. Secret values go to the system Keychain.</p></div><Button size="icon-sm" variant="ghost" aria-label="Close editor" onClick={onCancel} disabled={busy}><X /></Button></div></header><div className="oars-modal-body deploy-editor-body">
    <section className="deploy-form-section"><h3>Application</h3><div className="deploy-form-grid"><label htmlFor="deploy-app-name"><span>Name</span><input id="deploy-app-name" value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} /></label><label htmlFor="deploy-environment"><span>Environment</span><select id="deploy-environment" value={editor.environment} onChange={(event) => setEditor({ ...editor, environment: event.target.value as EditorState["environment"] })}><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select></label><label className="deploy-field-wide" htmlFor="deploy-folder"><span>Server folder</span><input id="deploy-folder" placeholder="/home/deploy/apps/storefront" value={editor.folder} onChange={(event) => setEditor({ ...editor, folder: event.target.value })} /><small>Use an absolute path. A folder under the connected user’s home usually needs fewer privileges.</small></label></div></section>
    <section className="deploy-form-section"><h3>Repository</h3><div className="deploy-form-grid"><label className="deploy-field-wide" htmlFor="deploy-repo"><span>Repository URL</span><input id="deploy-repo" value={editor.repo.url} placeholder="git@github.com:team/storefront.git" onChange={(event) => updateRepo({ url: event.target.value })} /></label><label htmlFor="deploy-transport"><span>Transport</span><select id="deploy-transport" value={editor.repo.transport} onChange={(event) => updateRepo({ transport: event.target.value as EditorState["repo"]["transport"] })}><option value="https">Public HTTPS</option><option value="ssh">Deploy key (SSH)</option></select></label><label htmlFor="deploy-branch"><span>Branch</span><input id="deploy-branch" value={editor.repo.branch} onChange={(event) => updateRepo({ branch: event.target.value })} /></label></div></section>
    <section className="deploy-form-section"><h3>Runtime</h3><div className="deploy-form-grid deploy-form-grid-three"><label htmlFor="deploy-type"><span>Application type</span><select id="deploy-type" value={editor.runtime.type} onChange={(event) => changeRuntimeType(event.target.value as EditorState["runtime"]["type"])}><option value="node">Node</option><option value="next">Next.js</option><option value="react">React SPA</option><option value="static">Static files</option></select></label><label htmlFor="deploy-node"><span>Node LTS major</span><select id="deploy-node" value={editor.runtime.node_version} onChange={(event) => updateRuntime({ node_version: event.target.value })}><option value="22">22 (Maintenance LTS)</option><option value="24">24 (Active LTS)</option></select><small>Preflight resolves the latest patch and checksum.</small></label><label htmlFor="deploy-package-manager"><span>Package manager</span><select id="deploy-package-manager" value={editor.runtime.package_manager} onChange={(event) => updateRuntime({ package_manager: event.target.value as EditorState["runtime"]["package_manager"] })}><option value="auto">Detect from lockfile</option><option value="npm">npm</option><option value="pnpm">pnpm</option><option value="yarn">Yarn</option></select></label>{(editor.runtime.type === "node" || editor.runtime.type === "next") && <><label htmlFor="deploy-entry"><span>Process entry</span><input id="deploy-entry" value={editor.runtime.entry} onChange={(event) => updateRuntime({ entry: event.target.value })} /></label><label htmlFor="deploy-args"><span>Entry arguments</span><input id="deploy-args" value={editor.runtime.args} onChange={(event) => updateRuntime({ args: event.target.value })} /></label><label className="deploy-field-wide" htmlFor="deploy-start-command"><span>Start command override</span><input id="deploy-start-command" value={editor.runtime.start_command} placeholder="Leave empty to use the structured entry and arguments" onChange={(event) => updateRuntime({ start_command: event.target.value })} /><small>A start override is shell code. Preflight shows it exactly before approval.</small></label></>}{(editor.runtime.type === "react" || editor.runtime.type === "static") && <label htmlFor="deploy-build-folder"><span>Build folder</span><input id="deploy-build-folder" value={editor.runtime.build_folder} onChange={(event) => updateRuntime({ build_folder: event.target.value })} /></label>}<label className="deploy-field-wide" htmlFor="deploy-install"><span>Install command override</span><input id="deploy-install" value={editor.runtime.install} placeholder="Leave empty for the frozen lockfile command" onChange={(event) => updateRuntime({ install: event.target.value })} /></label><label className="deploy-field-wide" htmlFor="deploy-build"><span>Build command</span><input id="deploy-build" value={editor.runtime.build} placeholder="npm run build" onChange={(event) => updateRuntime({ build: event.target.value })} /></label></div></section>
    <section className="deploy-form-section"><div className="deploy-form-section-heading"><div><h3>Environment variables</h3><p>Secret is the safe default. Values remain masked and local.</p></div><Button size="sm" variant="outline" onClick={() => setEditor({ ...editor, env_vars: [...editor.env_vars, { name: "", secret: true, value: "", has_value: false }] })}><Plus />Add variable</Button></div><div className="deploy-env-table">{editor.env_vars.map((row, index) => <div key={`${index}-${row.name}`} className="deploy-env-row"><label><span>Name</span><input aria-label={`Variable ${index + 1} name`} value={row.name} onChange={(event) => updateEnv(index, { name: event.target.value })} /></label><label><span>Value</span><input aria-label={`${row.name || `Variable ${index + 1}`} value`} type={row.secret ? "password" : "text"} autoComplete="off" placeholder={row.secret && row.has_value ? "Stored — unchanged" : "Value"} value={row.value} onChange={(event) => updateEnv(index, { value: event.target.value })} /></label><label className="deploy-secret-switch"><input type="checkbox" checked={row.secret} onChange={(event) => updateEnv(index, { secret: event.target.checked, has_value: event.target.checked ? row.has_value : row.value.length > 0 })} /><span><ShieldCheck />Secret</span></label><Button size="icon-sm" variant="ghost" aria-label={`Remove ${row.name || `variable ${index + 1}`}`} onClick={() => setEditor({ ...editor, env_vars: editor.env_vars.filter((_, rowIndex) => rowIndex !== index) })}><Trash2 /></Button></div>)}{!editor.env_vars.length && <div className="deploy-env-empty">No environment variables configured.</div>}</div><div className="deploy-bulk-import"><label htmlFor="deploy-bulk-env"><span>Import from .env</span><textarea id="deploy-bulk-env" rows={4} value={bulkText} placeholder={"API_URL=https://example.com\nDATABASE_URL=postgres://…"} onChange={(event) => { setBulkText(event.target.value); }} /></label><Button size="sm" variant="outline" onClick={onPreview} disabled={!bulkText}>Review import</Button>{bulkPreview && <div className="deploy-import-preview"><strong>Masked import preview</strong><pre>{bulkPreview.preview || "No valid variables found."}</pre>{bulkPreview.duplicates.length > 0 && <p role="alert">Duplicate names: {bulkPreview.duplicates.join(", ")}. Existing rows were not replaced.</p>}{bulkPreview.rejected.length > 0 && <p role="alert">Rejected {bulkPreview.rejected.length} invalid line{bulkPreview.rejected.length === 1 ? "" : "s"}.</p>}<Button size="sm" onClick={onApplyPreview} disabled={!bulkPreview.rows.length || bulkPreview.duplicates.length > 0 || bulkPreview.rejected.length > 0}>Add reviewed variables</Button></div>}</div></section>
    <section className="deploy-form-section"><h3>Public service</h3><div className="deploy-form-grid"><label className="deploy-field-wide" htmlFor="deploy-domains"><span>Domains</span><input id="deploy-domains" value={editor.domains.join(", ")} placeholder="example.com, www.example.com" onChange={(event) => setEditor({ ...editor, domains: event.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>{(editor.runtime.type === "node" || editor.runtime.type === "next") && <label htmlFor="deploy-port"><span>Application port</span><input id="deploy-port" type="number" min={1} max={65535} value={editor.app_port} onChange={(event) => setEditor({ ...editor, app_port: Number(event.target.value) })} /></label>}<label className="deploy-secret-switch deploy-ssl-switch"><input type="checkbox" checked={editor.ssl} onChange={(event) => setEditor({ ...editor, ssl: event.target.checked })} /><span><ShieldCheck />Issue SSL certificate</span></label>{editor.ssl && <label className="deploy-field-wide" htmlFor="deploy-email"><span>Certificate email</span><input id="deploy-email" type="email" value={editor.email} onChange={(event) => setEditor({ ...editor, email: event.target.value })} /></label>}</div></section>
    {error && <p className="oars-modal-error" role="alert">{error}</p>}
  </div><footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right"><Button variant="outline" onClick={onCancel} disabled={busy}>Cancel</Button><Button onClick={onSave} disabled={busy}>{busy ? <><LoaderCircle className="is-spinning" />Saving</> : "Save application"}</Button></div></footer></div></div>;
}

function DeleteDialog({ state, onCancel, onConfirm }: { state: DeleteState; onCancel: () => void; onConfirm: () => void }) {
  const dialogRef = useModalFocus(onCancel, "[data-delete-confirm]", !state.busy);
  return <div className="oars-modal-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !state.busy) onCancel(); }}><div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="deploy-delete-title" aria-describedby="deploy-delete-desc"><header className="oars-modal-header"><div className="oars-modal-title-row"><span className="oars-modal-icon oars-modal-icon-danger"><Trash2 /></span><div><h2 id="deploy-delete-title">Delete {state.app.name}?</h2><p id="deploy-delete-desc" className="oars-modal-subtitle">Oars will remove the local application definition and its Keychain values. Deployment history stays available.</p></div></div></header><div className="oars-modal-body"><div className="deploy-delete-resource"><Server /><div><strong>{state.app.name}</strong><span>{state.app.repo.url}</span></div></div>{state.error && <p className="oars-modal-error" role="alert">{state.error}</p>}</div><footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right"><Button variant="outline" onClick={onCancel} disabled={state.busy}>Keep application</Button><Button data-delete-confirm variant="destructive" onClick={onConfirm} disabled={state.busy}>{state.busy ? <><LoaderCircle className="is-spinning" />Deleting</> : "Delete application"}</Button></div></footer></div></div>;
}
