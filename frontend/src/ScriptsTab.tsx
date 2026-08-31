import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Eye,
  EyeOff,
  Pencil,
  Play,
  Plus,
  Search,
  Server as ServerIcon,
  ShieldAlert,
  Tag,
  Terminal,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import { api, BridgeError } from "./bridge";
import { OarsSelect } from "./components/ui/select";
import { useModalFocus } from "./components/useModalFocus";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import {
  appendOutput,
  detectVariables,
  filterScripts,
  formatLastRun,
  isDestructiveTagged,
  isValidColor,
  prefillRunValues,
  reconcileVariables,
  rememberRunValues,
  type RunValueMemory,
  SCRIPT_COLORS,
  summarizeBroadcast,
} from "./scripts-state";
import type {
  BroadcastPreview,
  BroadcastServerResult,
  Script,
  ScriptDraft,
  ScriptRunVars,
  ScriptVariable,
  Server,
  SessionStatus,
} from "./types";
import { Button } from "./components/ui/button";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";

const COLOR_LABEL: Record<string, string> = {
  "#d97757": "Clay",
  "#b98a2f": "Brass",
  "#3f6d7a": "Cobalt",
  "#5d7a52": "Moss",
  "#7a5c8f": "Plum",
  "#8a6f5c": "Tobacco",
};

const emptyDraft = (): ScriptDraft => ({
  name: "",
  description: "",
  tags: [],
  color: "",
  body: "",
  variables: [],
});

interface RunVarsDraft {
  values: Record<string, string>;
  promoted: Record<string, boolean>;
}

function varsFromDraft(draft: RunVarsDraft, definitions: ScriptVariable[]): ScriptRunVars {
  const vars: ScriptRunVars = {};
  for (const def of definitions) {
    // Stored secret_default is the minimum policy: those values stay
    // secret and masked; everything else may be promoted for this run.
    const secret = def.secret_default || draft.promoted[def.name] === true;
    vars[def.name] = { value: draft.values[def.name] ?? "", secret };
  }
  return vars;
}

type BroadcastFlow =
  | { step: "targets"; script: Script }
  | { step: "vars"; script: Script; targets: string[] }
  | { step: "confirm"; preview: BroadcastPreview }
  | { step: "destructive"; preview: BroadcastPreview }
  | {
      step: "running";
      runId: number;
      scriptName: string;
      servers: BroadcastServerResult[];
      outputs: Record<string, string>;
      gaps: Record<string, boolean>;
      cursors: Record<string, number>;
      canceled: boolean;
      done: boolean;
      error: string | null;
    };

export function ScriptsTab({
  serverId,
  servers,
  connected,
  statuses,
  onOpenServer,
  initialScriptId,
  initialDraft,
  onInitialDraftConsumed,
}: {
  serverId: string | null;
  servers: Server[];
  connected: boolean;
  statuses?: ReadonlyMap<string, SessionStatus>;
  onOpenServer?: (serverId: string) => void;
  /** Command-palette entry point (spec 06): preselect this script. */
  initialScriptId?: string | null;
  /** AI Terminal handoff: an unsaved exact command for user review. */
  initialDraft?: ScriptDraft | null;
  onInitialDraftConsumed?: () => void;
}) {
  const [scripts, setScripts] = useState<Script[]>([]);
  const [q, setQ] = useState("");
  const [tagFilter, setTagFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);

  const [editor, setEditor] = useState<ScriptDraft | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [editorSaving, setEditorSaving] = useState(false);
  const [editorValidation, setEditorValidation] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Script | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Single-server run: variable dialog state plus the live output pane.
  const [runScript, setRunScript] = useState<Script | null>(null);
  const [runVars, setRunVars] = useState<RunVarsDraft | null>(null);
  const [runVarsError, setRunVarsError] = useState<string | null>(null);
  const [runPane, setRunPane] = useState<{
    script: Script;
    channel: number;
    output: string;
    cursor: number;
    gapReported: boolean;
    exit: number | null;
    eof: boolean;
    error: string | null;
    startedAt: number;
  } | null>(null);

  // Broadcast flow (two-phase, spec 06 §5).
  const [flow, setFlow] = useState<BroadcastFlow | null>(null);
  const [targetSelection, setTargetSelection] = useState<Set<string>>(new Set());
  const [flowBusy, setFlowBusy] = useState(false);
  const [flowError, setFlowError] = useState<string | null>(null);

  const lastUsedRef = useRef<RunValueMemory>({});
  const runCursorRef = useRef(0);
  const runSeqRef = useRef(0);
  const runTimerRef = useRef<number | null>(null);
  const runPaneRef = useRef<typeof runPane>(null);
  const broadcastTimerRef = useRef<number | null>(null);
  const flowRef = useRef<BroadcastFlow | null>(null);
  const validationSeqRef = useRef(0);
  runPaneRef.current = runPane;
  flowRef.current = flow;

  const currentServer = useMemo(
    () => (serverId ? servers.find((s) => s.id === serverId) ?? null : null),
    [serverId, servers]
  );

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.scripts.list();
      setScripts(r.scripts);
      setRecoveryError(r.recovery_error ?? null);
      setError(null);
      setSelectedId((prev) => (prev && r.scripts.some((s) => s.id === prev) ? prev : (r.scripts[0]?.id ?? null)));
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setHasLoaded(true);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, serverId]);

  // Command-palette entry: preselect the requested script once loaded.
  useEffect(() => {
    if (initialScriptId && scripts.some((s) => s.id === initialScriptId)) {
      setSelectedId(initialScriptId);
    }
  }, [initialScriptId, scripts]);

  useEffect(() => {
    if (!initialDraft) return;
    setEditor({
      ...initialDraft,
      tags: [...initialDraft.tags],
      variables: initialDraft.variables.map((variable) => ({ ...variable })),
    });
    setEditorError(null);
    setEditorValidation(null);
    onInitialDraftConsumed?.();
  }, [initialDraft, onInitialDraftConsumed]);

  // Every timer and prepared/run record is owned by this view. Server
  // changes and unmounts release them so no quota or channel is orphaned.
  useEffect(() => {
    return () => {
      runSeqRef.current += 1;
      if (runTimerRef.current !== null) window.clearTimeout(runTimerRef.current);
      if (broadcastTimerRef.current !== null) window.clearInterval(broadcastTimerRef.current);
      const pane = runPaneRef.current;
      if (serverId && pane) api.ssh.closeChannel(serverId, pane.channel).catch(() => {});
      const currentFlow = flowRef.current;
      if (currentFlow?.step === "running" && !currentFlow.done) {
        api.scripts.broadcastCancel(currentFlow.runId).catch(() => {});
      } else if (currentFlow?.step === "confirm" || currentFlow?.step === "destructive") {
        api.scripts.broadcastPrepareCancel(currentFlow.preview.preview_id).catch(() => {});
      }
    };
  }, [serverId]);

  const selected = useMemo(
    () => scripts.find((s) => s.id === selectedId) ?? null,
    [scripts, selectedId]
  );
  const tags = useMemo(
    () => [...new Set(scripts.flatMap((script) => script.tags))].sort((a, b) => a.localeCompare(b)),
    [scripts]
  );
  const filtered = useMemo(() => filterScripts(scripts, q, tagFilter), [scripts, q, tagFilter]);
  const summary = useMemo(
    () => (flow && flow.step === "running" ? summarizeBroadcast(flow.servers) : null),
    [flow]
  );

  const [focusedScriptIndex, setFocusedScriptIndex] = useState(0);

  useEffect(() => {
    setFocusedScriptIndex((prev) => {
      if (filtered.length === 0) return 0;
      if (prev >= filtered.length) return filtered.length - 1;
      return prev;
    });
  }, [filtered.length]);

  // ── server context (spec 06: never a hidden first-server fallback) ──
  if (!serverId) {
    return (
      <div className="scripts scripts-no-context">
        <div className="empty-state">
          <div className="empty-icon"><ServerIcon /></div>
          <h3>Choose a server to run scripts</h3>
          <p>Scripts run against a connected server. Pick one to continue.</p>
          <div className="scripts-server-picker">
            {servers.map((s) => (
              <button key={s.id} className="scripts-server-option" onClick={() => onOpenServer?.(s.id)}>
                <span className="scripts-server-option-name">{s.name}</span>
                <span className="muted">{s.user}@{s.host}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (loading && !hasLoaded) {
    return <OarsLoadingState title="Loading scripts" detail="Oars is reading the local automation library." />;
  }

  const openEditor = (script: Script | ScriptDraft | null) => {
    if (!script) {
      setEditor(emptyDraft());
    } else {
      setEditor({
        id: script.id,
        name: script.name,
        description: script.description,
        tags: [...script.tags],
        color: script.color,
        body: script.body,
        variables: script.variables.map((v) => ({ ...v })),
      });
    }
    setEditorError(null);
    setEditorValidation(null);
  };

  const handleEditorBodyChange = (body: string) => {
    setEditor((prev) => {
      if (!prev) return prev;
      return { ...prev, body, variables: reconcileVariables(detectVariables(body), prev.variables) };
    });
    const seq = ++validationSeqRef.current;
    if (!body) {
      setEditorValidation(null);
      return;
    }
    api.scripts.validate(body).then(
      () => { if (validationSeqRef.current === seq) setEditorValidation(null); },
      (reason) => {
        if (validationSeqRef.current === seq) {
          setEditorValidation(reason instanceof BridgeError ? reason.message : String(reason));
        }
      }
    );
  };

  const handleSave = async () => {
    if (!editor) return;
    if (!editor.name.trim() || !editor.body) {
      setEditorError("Name and body are required");
      return;
    }
    setEditorSaving(true);
    setEditorError(null);
    try {
      await api.scripts.validate(editor.body);
      await api.scripts.save({
        ...editor,
        name: editor.name.trim(),
        // The body is NOT trimmed: leading/trailing whitespace can be
        // meaningful shell input (spec 06 — no silent edits).
      });
      setEditor(null);
      load();
    } catch (e) {
      setEditorError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setEditorSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await api.scripts.delete(deleteTarget.id);
      setDeleteTarget(null);
      load();
    } catch (e) {
      setDeleteError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setDeleteBusy(false);
    }
  };

  const canRun = connected && currentServer !== null;
  const canBroadcast = servers.some((server) => (statuses?.get(server.id) ?? (server.id === serverId && connected ? "ready" : "closed")) === "ready");

  const handleRunClick = (script: Script) => {
    if (!canRun) {
      setError("Connect this server before running scripts.");
      return;
    }
    setRunScript(script);
    setRunVars(prefillRunValues(lastUsedRef.current, script));
    setRunVarsError(null);
  };

  const startSingleRun = async (script: Script, vars: ScriptRunVars) => {
    if (!serverId) return;
    setRunVars(null);
    setRunScript(null);
    try {
      const r = await api.scripts.run(serverId, script.id, vars);
      lastUsedRef.current = rememberRunValues(lastUsedRef.current, script, vars);
      const seq = ++runSeqRef.current;
      runCursorRef.current = 0;
      if (runTimerRef.current !== null) window.clearTimeout(runTimerRef.current);
      setRunPane({
        script,
        channel: r.channel,
        output: "",
        cursor: 0,
        gapReported: false,
        exit: null,
        eof: false,
        error: null,
        startedAt: Date.now(),
      });
      await pollRunChannel(r.channel, seq);
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  };

  // The run pane poll loop: cumulative output with absolute cursors.
  // Recursive setTimeout keeps the loop stoppable by the seq guard; a
  // server change or unmount bumps the seq and stops it.
  const pollRunChannel = async (channel: number, seq: number) => {
    if (!serverId) return;
    try {
      const pr = await api.ssh.poll(serverId, [{ channel, cursor: runCursorRef.current }], false);
      if (runSeqRef.current !== seq) return;
      const ch = pr.channels.find((c) => c.id === channel);
      if (!ch) {
        setRunPane((prev) => (prev && prev.channel === channel ? { ...prev, error: "channel closed", eof: true } : prev));
        return;
      }
      setRunPane((prev) => {
        if (!prev || prev.channel !== channel) return prev;
        const appended = appendOutput(prev.output, ch.data, ch.dropped, prev.gapReported);
        return {
          ...prev,
          output: appended.text,
          gapReported: appended.gapReported,
          cursor: ch.cursor,
          exit: ch.exit,
          eof: ch.eof,
        };
      });
      runCursorRef.current = ch.cursor;
      if (ch.eof) return;
      runTimerRef.current = window.setTimeout(() => pollRunChannel(channel, seq), 500);
    } catch (e) {
      if (runSeqRef.current !== seq) return;
      setRunPane((prev) =>
        prev && prev.channel === channel
          ? { ...prev, error: e instanceof BridgeError ? e.message : String(e), eof: true }
          : prev
      );
    }
  };

  const closeRunPane = async () => {
    runSeqRef.current += 1;
    if (runTimerRef.current !== null) {
      window.clearTimeout(runTimerRef.current);
      runTimerRef.current = null;
    }
    if (serverId && runPane) {
      api.ssh.closeChannel(serverId, runPane.channel).catch(() => {});
    }
    setRunPane(null);
  };

  const retrySingleRun = () => {
    const script = runPane?.script;
    void closeRunPane();
    if (script) handleRunClick(script);
  };

  const copyOutput = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard can be denied; the pane stays readable */
    }
  };

  // ── broadcast: selection → vars → prepare → confirm → running ──
  const startBroadcast = (script: Script) => {
    if (!canBroadcast) {
      setError("Connect at least one server before broadcasting scripts.");
      return;
    }
    setTargetSelection(new Set());
    setFlowError(null);
    setFlow({ step: "targets", script });
  };

  const confirmTargets = (targets: string[]) => {
    if (flow?.step !== "targets") return;
    setRunVars(prefillRunValues(lastUsedRef.current, flow.script));
    setFlowError(null);
    setFlow({ step: "vars", script: flow.script, targets });
  };

  const prepareBroadcast = async (script: Script, targets: string[], draft: RunVarsDraft) => {
    setFlowBusy(true);
    setFlowError(null);
    try {
      const vars = varsFromDraft(draft, script.variables);
      const preview = await api.scripts.broadcastPrepare(script.id, targets, vars);
      lastUsedRef.current = rememberRunValues(lastUsedRef.current, script, vars);
      setRunVars(null);
      setFlow({ step: "confirm", preview });
    } catch (e) {
      setFlowError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setFlowBusy(false);
    }
  };

  const confirmPrepared = (preview: BroadcastPreview) => {
    if (preview.destructive) {
      setFlow({ step: "destructive", preview });
      return;
    }
    void commitBroadcast(preview);
  };

  const commitBroadcast = async (preview: BroadcastPreview) => {
    setFlowBusy(true);
    setFlowError(null);
    try {
      const r = await api.scripts.broadcast(preview.preview_id);
      setFlow({
        step: "running",
        runId: r.run_id,
        scriptName: preview.script_name,
        servers: preview.servers.map((s) => ({
          server_id: s.server_id,
          status: "queued",
          exit: null,
          error: "",
        })),
        outputs: {},
        gaps: {},
        cursors: {},
        canceled: false,
        done: false,
        error: null,
      });
      startBroadcastPolling(r.run_id);
    } catch (e) {
      setFlowError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      setFlowBusy(false);
    }
  };

  const cancelPrepared = async (preview: BroadcastPreview) => {
    setFlow(null);
    api.scripts.broadcastPrepareCancel(preview.preview_id).catch(() => {});
  };

  const startBroadcastPolling = (runId: number) => {
    if (broadcastTimerRef.current !== null) window.clearInterval(broadcastTimerRef.current);
    const tick = async () => {
      const current = flowRef.current;
      if (!current || current.step !== "running" || current.runId !== runId) return;
      try {
        const r = await api.scripts.broadcastPoll(runId, current.cursors);
        if (!flowRef.current || flowRef.current.step !== "running" || flowRef.current.runId !== runId) return;
        const cursors: Record<string, number> = { ...current.cursors };
        const outputs = { ...current.outputs };
        const gaps = { ...current.gaps };
        const servers = r.servers;
        for (const s of servers) {
          if (s.cursor !== undefined) cursors[s.server_id] = s.cursor;
          if (s.data !== undefined) {
            const appended = appendOutput(outputs[s.server_id] ?? "", s.data, s.gap, gaps[s.server_id] === true);
            outputs[s.server_id] = appended.text;
            gaps[s.server_id] = appended.gapReported;
          }
        }
        setFlow({
          step: "running",
          runId,
          scriptName: r.script_name || current.scriptName,
          servers,
          outputs,
          gaps,
          cursors,
          canceled: r.canceled,
          done: r.done,
          error: null,
        });
        if (r.done) {
          if (broadcastTimerRef.current !== null) {
            window.clearInterval(broadcastTimerRef.current);
            broadcastTimerRef.current = null;
          }
        }
      } catch (e) {
        if (!flowRef.current || flowRef.current.step !== "running" || flowRef.current.runId !== runId) return;
        setFlow((prev) =>
          prev && prev.step === "running"
            ? { ...prev, error: e instanceof BridgeError ? e.message : String(e) }
            : prev
        );
        if (broadcastTimerRef.current !== null) {
          window.clearInterval(broadcastTimerRef.current);
          broadcastTimerRef.current = null;
        }
      }
    };
    broadcastTimerRef.current = window.setInterval(tick, 800);
    tick();
  };

  const cancelBroadcastRun = async () => {
    const current = flowRef.current;
    if (!current || current.step !== "running") return;
    try {
      await api.scripts.broadcastCancel(current.runId);
    } catch {
      /* the poll loop reports the real state */
    }
  };

  const closeBroadcastRun = () => {
    const current = flowRef.current;
    if (current?.step === "running" && !current.done) return;
    if (broadcastTimerRef.current !== null) {
      window.clearInterval(broadcastTimerRef.current);
      broadcastTimerRef.current = null;
    }
    setFlow(null);
  };

  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? id;

  const handleScriptRowKeyDown = (event: React.KeyboardEvent, scriptId: string, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(filtered.length - 1, index + 1);
      setFocusedScriptIndex(next);
      const btns = document.querySelectorAll<HTMLButtonElement>(".scripts-library .scripts-row");
      btns[next]?.focus();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedScriptIndex(prev);
      const btns = document.querySelectorAll<HTMLButtonElement>(".scripts-library .scripts-row");
      btns[prev]?.focus();
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setFocusedScriptIndex(0);
      const btns = document.querySelectorAll<HTMLButtonElement>(".scripts-library .scripts-row");
      btns[0]?.focus();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      const last = filtered.length - 1;
      setFocusedScriptIndex(last);
      const btns = document.querySelectorAll<HTMLButtonElement>(".scripts-library .scripts-row");
      btns[last]?.focus();
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setSelectedId(scriptId);
      return;
    }
  };

  return (
    <div className="scripts">
      <div className="scripts-toolbar">
        <div className="scripts-search">
          <Search size={14} />
          <input
            type="text"
            placeholder="Search scripts…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown" || e.key === "Enter") {
                e.preventDefault();
                const first = document.querySelector<HTMLButtonElement>(".scripts-library .scripts-row");
                first?.focus();
              }
            }}
            aria-label="Search scripts"
          />
        </div>
        <label className="scripts-tag-filter">
          <Tag size={14} aria-hidden />
          <OarsSelect aria-label="Filter scripts by tag" value={tagFilter} onValueChange={setTagFilter} options={[{ value: "", label: "All tags" }, ...tags.map((tag) => ({ value: tag, label: tag }))]} />
        </label>
        {loading && <OarsRefreshStatus label="Updating scripts" />}
        <Button size="sm" onClick={() => openEditor(null)}><Plus />New script</Button>
      </div>

      {error && <div className="scripts-inline-error" role="alert">{error}</div>}
      {recoveryError && (
        <div className="scripts-inline-error" role="alert">
          <AlertTriangle size={14} /> {recoveryError}
        </div>
      )}

      {scripts.length === 0 && hasLoaded && !loading ? (
        <div className="scripts-empty">
          <div className="empty-state">
            <div className="empty-icon"><Terminal /></div>
            <h3>Save your first script</h3>
            <p>A personal library of shell commands with <code>{`{{variables}}`}</code>, run on one server or broadcast across the fleet.</p>
            <Button onClick={() => openEditor({ ...emptyDraft(), name: "Tail error logs", body: "sudo tail -f /var/log/{{service}}/error.log", variables: [{ name: "service", label: "Service", secret_default: false }] })}>
              Start with an example
            </Button>
          </div>
        </div>
      ) : filtered.length === 0 && hasLoaded && !loading ? (
        <div className="scripts-empty">
          <div className="empty-state">
            <div className="empty-icon"><Search /></div>
            <h3>No matching scripts</h3>
            <p>Change the search text or tag filter to see the rest of your library.</p>
            <Button variant="outline" onClick={() => { setQ(""); setTagFilter(""); }}>Clear filters</Button>
          </div>
        </div>
      ) : (
        <div className="scripts-layout">
          <div className="scripts-library" role="listbox" aria-label="Script library">
            {filtered.map((s, index) => {
              const isSelected = s.id === selectedId;
              const isFocused = index === focusedScriptIndex || (focusedScriptIndex === -1 && isSelected);
              return (
                <button
                  key={s.id}
                  role="option"
                  tabIndex={isFocused ? 0 : -1}
                  aria-selected={isSelected}
                  className={`scripts-row ${isSelected ? "selected" : ""}`}
                  onFocus={() => setFocusedScriptIndex(index)}
                  onClick={() => setSelectedId(s.id)}
                  onKeyDown={(e) => handleScriptRowKeyDown(e, s.id, index)}
                >
                  <span className="scripts-row-color" style={{ background: s.color || "transparent" }} aria-hidden />
                  <span className="scripts-row-main">
                    <span className="scripts-row-name">{s.name}</span>
                    <span className="scripts-row-meta muted">
                      {s.run_count} runs · {formatLastRun(s.last_run_at, s.run_count)}
                      {isDestructiveTagged(s.tags) && <span className="scripts-destructive-tag">destructive</span>}
                    </span>
                  </span>
                  {s.tags.length > 0 && (
                    <span className="scripts-row-tags">
                      {s.tags.slice(0, 3).map((t) => <span key={t} className="scripts-tag">{t}</span>)}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="scripts-detail" aria-live="polite">
            {selected ? (
              <>
                <div className="scripts-detail-head">
                  <div>
                    <h3 className="scripts-detail-title">{selected.name}</h3>
                    <p className="muted scripts-detail-meta">
                      {selected.description || "No description"}
                      {selected.tags.length > 0 && ` · ${selected.tags.join(", ")}`}
                    </p>
                  </div>
                  <div className="scripts-detail-actions">
                    <Button variant="ghost" size="sm" onClick={() => openEditor(selected)}><Pencil />Edit</Button>
                    <Button variant="ghost" size="sm" onClick={() => { setDeleteTarget(selected); setDeleteError(null); }}><Trash2 />Delete</Button>
                  </div>
                </div>
                <pre className="scripts-detail-body">{selected.body}</pre>
                <div className="scripts-detail-run">
                  <Button size="sm" onClick={() => handleRunClick(selected)} disabled={!canRun}><Play />Run</Button>
                  <Button size="sm" variant="outline" onClick={() => startBroadcast(selected)} disabled={!canBroadcast}>
                    <ServerIcon />Run on multiple servers…
                  </Button>
                  {!canRun && <span className="muted scripts-connect-hint">Connect this server for a single run.</span>}
                  {!canBroadcast && <span className="muted scripts-connect-hint">Connect a fleet target for broadcast.</span>}
                </div>
              </>
            ) : (
              <div className="muted scripts-detail-empty">Select a script to inspect it.</div>
            )}
          </div>
        </div>
      )}

      {/* ── editor modal (no data loss: full draft every save) ── */}
      {editor && (
        <EditorModal
          draft={editor}
          error={editorError}
          validationError={editorValidation}
          saving={editorSaving}
          onBodyChange={handleEditorBodyChange}
          onDraftChange={setEditor}
          onCancel={() => setEditor(null)}
          onSave={handleSave}
        />
      )}

      {/* ── delete confirmation ── */}
      {deleteTarget && (
        <DeleteModal
          script={deleteTarget}
          busy={deleteBusy}
          error={deleteError}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={handleDelete}
        />
      )}

      {/* ── single-run variable dialog ── */}
      {runScript && runVars && (
        <VarsModal
          script={runScript}
          draft={runVars}
          error={runVarsError}
          onDraftChange={setRunVars}
          onCancel={() => { setRunScript(null); setRunVars(null); }}
          onConfirm={(d) => startSingleRun(runScript, varsFromDraft(d, runScript.variables))}
          confirmLabel="Run"
        />
      )}

      {/* ── single-run output pane ── */}
      {runPane && (
        <RunPane
          title={runPane.script.name}
          serverName={currentServer?.name ?? ""}
          output={runPane.output}
          gapReported={runPane.gapReported}
          exit={runPane.exit}
          eof={runPane.eof}
          error={runPane.error}
          onCopy={() => copyOutput(runPane.output)}
          onClose={closeRunPane}
          onRetry={retrySingleRun}
        />
      )}

      {/* ── broadcast flow ── */}
      {flow?.step === "targets" && (
        <TargetsModal
          servers={servers}
          statuses={statuses}
          selection={targetSelection}
          onSelection={setTargetSelection}
          onCancel={() => setFlow(null)}
          onConfirm={() => confirmTargets([...targetSelection])}
        />
      )}
      {flow?.step === "vars" && (
        <VarsModal
          script={flow.script}
          draft={runVars ?? { values: {}, promoted: {} }}
          error={flowError}
          onDraftChange={(d) => { setRunVars(d); setFlowError(null); }}
          onCancel={() => setFlow(null)}
          onConfirm={(d) => prepareBroadcast(flow.script, flow.targets, d)}
          confirmLabel="Preview command"
        />
      )}
      {flow && (flow.step === "confirm" || flow.step === "destructive") && (
        <PreviewModal
          preview={flow.preview}
          destructive={flow.step === "destructive"}
          busy={flowBusy}
          error={flowError}
          serverName={serverName}
          onCancel={() => cancelPrepared(flow.preview)}
          onConfirm={() => flow.step === "confirm" ? confirmPrepared(flow.preview) : commitBroadcast(flow.preview)}
        />
      )}
      {flow?.step === "running" && (
        <BroadcastPane
          flow={flow}
          summary={summary}
          serverName={serverName}
          onCancel={cancelBroadcastRun}
          onClose={closeBroadcastRun}
          onRetry={() => startBroadcastPolling(flow.runId)}
        />
      )}
    </div>
  );
}

function DeleteModal({
  script,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  script: Script;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useModalFocus(onCancel, "[data-delete-first]", !busy);
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="scripts-delete-title" aria-describedby="scripts-delete-desc">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon oars-modal-icon-danger"><Trash2 /></span>
            <div>
              <h2 id="scripts-delete-title">Delete “{script.name}”?</h2>
              <p id="scripts-delete-desc" className="oars-modal-subtitle">The saved definition will be removed. Existing run history stays available.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel} disabled={busy}><X /></Button>
          </div>
        </header>
        {error && <p className="oars-modal-error" role="alert">{error}</p>}
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button data-delete-first variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
            <Button variant="destructive" onClick={onConfirm} disabled={busy}>{busy ? "Deleting…" : "Delete script"}</Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}

// ── editor modal ─────────────────────────────────────────────────────────────

function EditorModal({
  draft,
  error,
  validationError,
  saving,
  onBodyChange,
  onDraftChange,
  onCancel,
  onSave,
}: {
  draft: ScriptDraft;
  error: string | null;
  validationError: string | null;
  saving: boolean;
  onBodyChange: (body: string) => void;
  onDraftChange: (d: ScriptDraft) => void;
  onCancel: () => void;
  onSave: () => void;
}) {
  const dialogRef = useModalFocus(onCancel, "[data-editor-first]", !saving);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [insertName, setInsertName] = useState("");
  const [autocomplete, setAutocomplete] = useState<{ start: number; cursor: number; query: string } | null>(null);
  const detected = new Set(detectVariables(draft.body));

  const updateAutocomplete = (body: string, cursor: number) => {
    const start = body.lastIndexOf("{{", cursor - 1);
    const close = body.lastIndexOf("}}", cursor - 1);
    if (start < 0 || start <= close) {
      setAutocomplete(null);
      return;
    }
    const query = body.slice(start + 2, cursor);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$|^$/.test(query)) {
      setAutocomplete(null);
      return;
    }
    setAutocomplete({ start, cursor, query });
  };

  const autocompleteOptions = autocomplete
    ? draft.variables.filter((variable) => variable.name.toLowerCase().startsWith(autocomplete.query.toLowerCase()))
    : [];

  const completeVariable = (name: string) => {
    if (!autocomplete) return;
    const hasClosingBraces = draft.body.slice(autocomplete.cursor, autocomplete.cursor + 2) === "}}";
    const end = autocomplete.cursor + (hasClosingBraces ? 2 : 0);
    const placeholder = `{{${name}}}`;
    onBodyChange(`${draft.body.slice(0, autocomplete.start)}${placeholder}${draft.body.slice(end)}`);
    setAutocomplete(null);
    requestAnimationFrame(() => {
      const cursor = autocomplete.start + placeholder.length;
      textareaRef.current?.focus();
      textareaRef.current?.setSelectionRange(cursor, cursor);
    });
  };

  const insertVariable = () => {
    const name = insertName.trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return;
    const textarea = textareaRef.current;
    const start = textarea?.selectionStart ?? draft.body.length;
    const end = textarea?.selectionEnd ?? start;
    const placeholder = `{{${name}}}`;
    onBodyChange(`${draft.body.slice(0, start)}${placeholder}${draft.body.slice(end)}`);
    setInsertName("");
    requestAnimationFrame(() => {
      textarea?.focus();
      textarea?.setSelectionRange(start + placeholder.length, start + placeholder.length);
    });
  };

  const setVariable = (index: number, patch: Partial<ScriptVariable>) => {
    onDraftChange({
      ...draft,
      variables: draft.variables.map((v, i) => (i === index ? { ...v, ...patch } : v)),
    });
  };

  return (
    <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !saving) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal scripts-editor-modal" role="dialog" aria-modal="true" aria-labelledby="scripts-editor-title" aria-describedby="scripts-editor-subtitle">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon"><Pencil /></span>
            <div>
              <h2 id="scripts-editor-title">{draft.id ? "Edit script" : "New script"}</h2>
              <p id="scripts-editor-subtitle" className="oars-modal-subtitle">Saved locally; run-time values are never stored.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel} disabled={saving}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body scripts-editor-body">
          <div className="scripts-form-row">
            <label htmlFor="scripts-editor-name">Name</label>
            <input id="scripts-editor-name" data-editor-first type="text" maxLength={200} required value={draft.name} onChange={(e) => onDraftChange({ ...draft, name: e.target.value })} />
          </div>
          <div className="scripts-form-row">
            <label htmlFor="scripts-editor-desc">Description</label>
            <input id="scripts-editor-desc" type="text" maxLength={4096} value={draft.description} onChange={(e) => onDraftChange({ ...draft, description: e.target.value })} />
          </div>
          <div className="scripts-form-row">
            <label htmlFor="scripts-editor-tags">Tags</label>
            <input id="scripts-editor-tags" type="text" placeholder="logs, deploy, destructive…" value={draft.tags.join(", ")} onChange={(e) => onDraftChange({ ...draft, tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} />
          </div>
          <div className="scripts-form-row">
            <span className="scripts-form-label">Color</span>
            <div className="scripts-color-row" role="radiogroup" aria-label="Script color">
              <button
                type="button"
                role="radio"
                aria-checked={draft.color === ""}
                className={`scripts-color-swatch scripts-color-none ${draft.color === "" ? "selected" : ""}`}
                title="No color"
                onClick={() => onDraftChange({ ...draft, color: "" })}
              />
              {SCRIPT_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  role="radio"
                  aria-checked={draft.color === c}
                  aria-label={COLOR_LABEL[c]}
                  className={`scripts-color-swatch ${draft.color === c ? "selected" : ""}`}
                  style={{ background: c }}
                  onClick={() => onDraftChange({ ...draft, color: c })}
                />
              ))}
            </div>
          </div>
          <div className="scripts-form-row">
            <label htmlFor="scripts-editor-body">Command body — use {`{{variable}}`}</label>
            <textarea
              ref={textareaRef}
              id="scripts-editor-body"
              rows={8}
              className="scripts-editor-body-input"
              value={draft.body}
              onChange={(e) => {
                onBodyChange(e.target.value);
                updateAutocomplete(e.target.value, e.target.selectionStart);
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape" && autocomplete) {
                  e.preventDefault();
                  e.stopPropagation();
                  setAutocomplete(null);
                }
              }}
              onClick={(event) => updateAutocomplete(event.currentTarget.value, event.currentTarget.selectionStart)}
              onKeyUp={(event) => updateAutocomplete(event.currentTarget.value, event.currentTarget.selectionStart)}
              aria-invalid={validationError ? true : undefined}
              aria-describedby={validationError ? "scripts-editor-validation" : "scripts-editor-body-hint"}
              spellCheck={false}
            />
            {autocomplete && (
              <div className="scripts-variable-suggestions" role="listbox" aria-label="Variable suggestions">
                {autocompleteOptions.length > 0 ? autocompleteOptions.map((variable) => (
                  <button
                    key={variable.name}
                    type="button"
                    role="option"
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => completeVariable(variable.name)}
                  >
                    <code>{`{{${variable.name}}}`}</code>
                    <span>{variable.label || "Saved variable"}</span>
                  </button>
                )) : (
                  <span className="muted">Type a variable name, then close it with {`}}`}.</span>
                )}
              </div>
            )}
            <div className="scripts-variable-insert">
              <input
                type="text"
                aria-label="Variable name to insert"
                placeholder="service"
                value={insertName}
                onChange={(event) => setInsertName(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); insertVariable(); } }}
              />
              <Button type="button" size="sm" variant="outline" onClick={insertVariable} disabled={!/^[A-Za-z_][A-Za-z0-9_]*$/.test(insertName.trim())}>
                Insert {`{{variable}}`}
              </Button>
              <span id="scripts-editor-body-hint" className="muted">Adds a placeholder at the cursor.</span>
            </div>
            {validationError && <p id="scripts-editor-validation" className="oars-modal-error" role="alert">{validationError}</p>}
          </div>
          {draft.variables.length > 0 && (
            <div className="scripts-vars-table-wrap">
              <span className="scripts-form-label">Detected variables</span>
              <table className="scripts-vars-table">
                <thead>
                  <tr><th>Variable</th><th>Label</th><th>Secret default</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {draft.variables.map((v, i) => (
                    <tr key={v.name}>
                      <td><code>{`{{${v.name}}}`}</code></td>
                      <td><input type="text" aria-label={`Label for ${v.name}`} value={v.label} onChange={(e) => setVariable(i, { label: e.target.value })} /></td>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Secret default for ${v.name}`}
                          checked={v.secret_default}
                          onChange={(e) => setVariable(i, { secret_default: e.target.checked })}
                        />
                      </td>
                      <td><span className={detected.has(v.name) ? "scripts-variable-used" : "scripts-variable-unused"}>{detected.has(v.name) ? "Used" : "Unused"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted scripts-vars-hint">Secret defaults mask the input and keep the value out of audit and history — the stored default is the minimum policy.</p>
            </div>
          )}
          {error && <p className="oars-modal-error" role="alert">{error}</p>}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onCancel} disabled={saving}>Cancel</Button>
            <Button onClick={onSave} disabled={saving || !!validationError}>{saving ? "Saving…" : "Save script"}</Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}

// ── variable values dialog (run + broadcast) ─────────────────────────────────

function VarsModal({
  script,
  draft,
  error,
  onDraftChange,
  onCancel,
  onConfirm,
  confirmLabel,
}: {
  script: Script;
  draft: RunVarsDraft;
  error: string | null;
  onDraftChange: (d: RunVarsDraft) => void;
  onCancel: () => void;
  onConfirm: (d: RunVarsDraft) => void;
  confirmLabel: string;
}) {
  const dialogRef = useModalFocus(onCancel, "[data-vars-first]");

  if (script.variables.length === 0) {
    // No variables: confirm directly (spec 06 — no prompt for nothing).
    return (
      <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
        <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="scripts-vars-title" aria-describedby="scripts-vars-subtitle">
          <header className="oars-modal-header">
            <div className="oars-modal-title-row">
              <span className="oars-modal-icon"><Play /></span>
              <div>
                <h2 id="scripts-vars-title">{script.name}</h2>
                <p id="scripts-vars-subtitle" className="oars-modal-subtitle">This script has no variables.</p>
              </div>
            </div>
          </header>
          <footer className="oars-modal-actions">
            <div className="oars-modal-actions-right">
              <Button variant="ghost" onClick={onCancel}>Cancel</Button>
              <Button data-vars-first onClick={() => onConfirm(draft)}>{confirmLabel}</Button>
            </div>
          </footer>
          {error && <p className="oars-modal-error" role="alert">{error}</p>}
        </div>
      </ApplicationOverlay>
    );
  }

  return (
    <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal scripts-vars-modal" role="dialog" aria-modal="true" aria-labelledby="scripts-vars-title" aria-describedby="scripts-vars-subtitle">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon"><Play /></span>
            <div>
              <h2 id="scripts-vars-title">Values for “{script.name}”</h2>
              <p id="scripts-vars-subtitle" className="oars-modal-subtitle">Used for this run only — never saved.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body scripts-vars-body">
          {script.variables.map((v, i) => {
            const locked = v.secret_default;
            const isSecret = locked || draft.promoted[v.name] === true;
            return (
              <div className="scripts-var-row" key={v.name}>
                <label htmlFor={`scripts-var-${v.name}`}>
                  <code>{`{{${v.name}}}`}</code>
                  {v.label && <span className="muted">{v.label}</span>}
                  {locked && <span className="scripts-secret-lock" title="Stored as a secret default — cannot be demoted"><ShieldAlert size={12} />secret</span>}
                </label>
                <div className="scripts-var-input-row">
                  <input
                    id={`scripts-var-${v.name}`}
                    data-vars-first={i === 0 ? "" : undefined}
                    type={isSecret ? "password" : "text"}
                    value={draft.values[v.name] ?? ""}
                    onChange={(e) => onDraftChange({ ...draft, values: { ...draft.values, [v.name]: e.target.value } })}
                    autoComplete="off"
                    required
                  />
                  {!locked && (
                    <label className="scripts-promote">
                      <input
                        type="checkbox"
                        checked={draft.promoted[v.name] === true}
                        onChange={(e) => onDraftChange({ ...draft, promoted: { ...draft.promoted, [v.name]: e.target.checked } })}
                      />
                      {isSecret ? <EyeOff size={12} /> : <Eye size={12} />}
                      secret
                    </label>
                  )}
                </div>
              </div>
            );
          })}
          {error && <p className="oars-modal-error" role="alert">{error}</p>}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
            <Button onClick={() => onConfirm(draft)}>{confirmLabel}</Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}

// ── broadcast preview / confirm modal ────────────────────────────────────────

function PreviewModal({
  preview,
  destructive,
  busy,
  error,
  serverName,
  onCancel,
  onConfirm,
}: {
  preview: BroadcastPreview;
  destructive: boolean;
  busy: boolean;
  error: string | null;
  serverName: (id: string) => string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [showCommand, setShowCommand] = useState(false);
  const hasSecrets = preview.command !== preview.redacted_command;
  const dialogRef = useModalFocus(onCancel, "[data-preview-confirm]", !busy);

  const command = hasSecrets && !showCommand ? preview.redacted_command : preview.command;

  return (
    <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal scripts-preview-modal" role="dialog" aria-modal="true" aria-labelledby="scripts-preview-title" aria-describedby="scripts-preview-desc">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className={`oars-modal-icon ${destructive ? "oars-modal-icon-danger" : ""}`}>
              {destructive ? <AlertTriangle /> : <Terminal />}
            </span>
            <div>
              <h2 id="scripts-preview-title">
                {destructive ? "Confirm destructive broadcast" : `Run “${preview.script_name}” on ${preview.servers.length} server${preview.servers.length === 1 ? "" : "s"}?`}
              </h2>
              <p id="scripts-preview-desc" className="oars-modal-subtitle">
                This preview is the exact command Oars will submit. It does not contact a remote shell and is not a dry run — each server still runs a <code>bash -n</code> syntax check after confirmation.
              </p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel} disabled={busy}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body scripts-preview-body">
          <div className="scripts-preview-command">
            <span>Command</span>
            <code>{command}</code>
            {hasSecrets && (
              <button className="scripts-reveal" onClick={() => setShowCommand((v) => !v)}>
                {showCommand ? <><EyeOff size={12} />hide values</> : <><Eye size={12} />show values</>}
              </button>
            )}
          </div>
          <div className="scripts-preview-targets">
            <span>Targets</span>
            <ul>
              {preview.servers.map((s) => (
                <li key={s.server_id}>{serverName(s.server_id)}</li>
              ))}
            </ul>
          </div>
          {destructive && (
            <p className="scripts-destructive-warning" role="alert">
              This script carries the “destructive” tag. It may delete or modify data. Review the command and targets before confirming.
            </p>
          )}
          {error && <p className="oars-modal-error" role="alert">{error}</p>}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onCancel} disabled={busy}>Back</Button>
            <Button data-preview-confirm variant={destructive ? "destructive" : "default"} onClick={onConfirm} disabled={busy}>
              {busy ? "Starting…" : destructive ? "Confirm destructive run" : preview.destructive ? "Continue to safety check" : `Run on ${preview.servers.length} server${preview.servers.length === 1 ? "" : "s"}`}
            </Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}

// ── broadcast target selection modal ─────────────────────────────────────────

function TargetsModal({
  servers,
  statuses,
  selection,
  onSelection,
  onCancel,
  onConfirm,
}: {
  servers: Server[];
  statuses?: ReadonlyMap<string, SessionStatus>;
  selection: Set<string>;
  onSelection: (s: Set<string>) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useModalFocus(onCancel, "[data-targets-first]");
  const groups = useMemo(() => {
    const map = new Map<string, Server[]>();
    for (const s of servers) {
      const g = s.group || "Ungrouped";
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(s);
    }
    return [...map.entries()];
  }, [servers]);

  const toggle = (id: string) => {
    if (statuses?.get(id) !== "ready") return;
    const next = new Set(selection);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelection(next);
  };

  const toggleGroup = (groupServers: Server[]) => {
    const available = groupServers.filter((server) => statuses?.get(server.id) === "ready");
    const next = new Set(selection);
    const allSelected = available.length > 0 && available.every((s) => next.has(s.id));
    for (const s of available) {
      if (allSelected) next.delete(s.id);
      else next.add(s.id);
    }
    onSelection(next);
  };

  return (
    <ApplicationOverlay role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal scripts-targets-modal" role="dialog" aria-modal="true" aria-labelledby="scripts-targets-title" aria-describedby="scripts-targets-subtitle">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon"><ServerIcon /></span>
            <div>
              <h2 id="scripts-targets-title">Select servers</h2>
              <p id="scripts-targets-subtitle" className="oars-modal-subtitle">Every selected server runs the same prepared command.</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body scripts-targets-body">
          {groups.map(([group, groupServers]) => {
            const available = groupServers.filter((server) => statuses?.get(server.id) === "ready");
            const allSelected = available.length > 0 && available.every((s) => selection.has(s.id));
            const someSelected = available.some((s) => selection.has(s.id));
            return (
              <div key={group} className="scripts-target-group">
                <button className="scripts-target-group-head" onClick={() => toggleGroup(groupServers)} disabled={available.length === 0} aria-pressed={allSelected}>
                  <span className={`scripts-checkbox ${allSelected ? "checked" : someSelected ? "partial" : ""}`} aria-hidden />
                  <span className="scripts-target-group-name">{group}</span>
                  <span className="muted">{groupServers.length}</span>
                </button>
                {groupServers.map((s) => {
                  const status = statuses?.get(s.id) ?? "closed";
                  const availableTarget = status === "ready";
                  return (
                  <label key={s.id} className={`scripts-target-row ${availableTarget ? "" : "unavailable"}`}>
                    <input
                      type="checkbox"
                      checked={selection.has(s.id)}
                      onChange={() => toggle(s.id)}
                      disabled={!availableTarget}
                      data-targets-first={selection.size === 0 && s === available[0] ? "" : undefined}
                    />
                    <span className="scripts-target-name">{s.name}</span>
                    <span className="muted">{s.user}@{s.host}</span>
                    <span className={`scripts-target-status ${availableTarget ? "ready" : "offline"}`}>{availableTarget ? "Connected" : "Unavailable"}</span>
                  </label>
                  );
                })}
              </div>
            );
          })}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
            <Button onClick={onConfirm} disabled={selection.size === 0}>
              Continue with {selection.size} server{selection.size === 1 ? "" : "s"}
            </Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}

// ── single-run output pane ───────────────────────────────────────────────────

function RunPane({
  title,
  serverName,
  output,
  gapReported,
  exit,
  eof,
  error,
  onCopy,
  onClose,
  onRetry,
}: {
  title: string;
  serverName: string;
  output: string;
  gapReported: boolean;
  exit: number | null;
  eof: boolean;
  error: string | null;
  onCopy: () => void;
  onClose: () => void;
  onRetry: () => void;
}) {
  const status = error ? "failed" : eof ? (exit === 0 ? "done" : "failed") : "running";
  return (
    <section className="scripts-run-pane" aria-label={`Output of ${title}`}>
      <header className="scripts-run-head">
        <div>
          <strong>{title}</strong>
          <span className="muted">{serverName}</span>
        </div>
        <div className="scripts-run-status">
          {status === "running" && <span className="scripts-status-pill running" role="status" aria-live="polite"><Clock size={12} />running</span>}
          {status === "done" && <span className="scripts-status-pill done" role="status" aria-live="polite"><CheckCircle2 size={12} />exit 0</span>}
          {status === "failed" && <span className="scripts-status-pill failed" role="status" aria-live="polite"><XCircle size={12} />{error ?? `exit ${exit ?? "?"}`}</span>}
          {gapReported && <span className="scripts-gap-warning" title="Some output was dropped by the retention buffer">output gap</span>}
          {(eof || error) && <Button variant="outline" size="sm" onClick={onRetry}>Run again</Button>}
          <Button variant="ghost" size="icon-sm" aria-label="Copy output" onClick={onCopy}><Copy /></Button>
          <Button variant="ghost" size="icon-sm" aria-label="Close output" onClick={onClose}><X /></Button>
        </div>
      </header>
      <pre className="scripts-run-output" role="log" aria-live="polite" aria-atomic="false" tabIndex={0} aria-label="Script execution output">{output || (eof ? "(no output)" : "Waiting for output…")}</pre>
    </section>
  );
}

// ── broadcast results pane ───────────────────────────────────────────────────

function BroadcastPane({
  flow,
  summary,
  serverName,
  onCancel,
  onClose,
  onRetry,
}: {
  flow: Extract<BroadcastFlow, { step: "running" }>;
  summary: ReturnType<typeof summarizeBroadcast> | null;
  serverName: (id: string) => string;
  onCancel: () => void;
  onClose: () => void;
  onRetry: () => void;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggle = (id: string) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  const statusIcon = (s: BroadcastServerResult) => {
    switch (s.status) {
      case "done":
        return <CheckCircle2 size={14} className="scripts-status-icon done" />;
      case "failed":
        return <XCircle size={14} className="scripts-status-icon failed" />;
      case "canceled":
        return <X size={14} className="scripts-status-icon canceled" />;
      case "skipped":
        return <AlertTriangle size={14} className="scripts-status-icon skipped" />;
      case "checking":
        return <Clock size={14} className="scripts-status-icon checking" />;
      case "running":
        return <Terminal size={14} className="scripts-status-icon running" />;
      default:
        return <Clock size={14} className="scripts-status-icon queued" />;
    }
  };

  const statusLabel = (s: BroadcastServerResult) => {
    switch (s.status) {
      case "checking":
        return "checking syntax";
      case "running":
        return "running";
      case "done":
        return s.exit === 0 ? "exit 0" : `exit ${s.exit ?? "?"}`;
      case "failed":
        return s.error || `exit ${s.exit ?? "?"}`;
      case "canceled":
        return s.error || "canceled";
      case "skipped":
        return s.error || "skipped";
      default:
        return "queued";
    }
  };

  return (
    <section className="scripts-broadcast-pane" aria-label="Broadcast results">
      <header className="scripts-run-head">
        <div>
          <strong>{flow.scriptName}</strong>
          <span className="muted">broadcast · {summary ? `${summary.done + summary.failed + summary.canceled + summary.skipped}/${summary.total} finished` : ""}</span>
        </div>
        <div className="scripts-run-status">
          {!flow.done && <span className="scripts-status-pill running" role="status" aria-live="polite"><Clock size={12} />running</span>}
          {flow.done && summary && (
            <span className="scripts-status-pill done" role="status" aria-live="polite">
              <CheckCircle2 size={12} />
              {summary.failed === 0 && summary.canceled === 0 && summary.skipped === 0
                ? `${summary.done}/${summary.total} succeeded`
                : `${summary.done} ok · ${summary.failed} failed · ${summary.canceled} canceled · ${summary.skipped} skipped`}
            </span>
          )}
          {flow.error && <span className="scripts-gap-warning" role="alert">{flow.error}</span>}
          {flow.error && <Button variant="outline" size="sm" onClick={onRetry}>Retry status</Button>}
          {!flow.done && (
            <Button variant="outline" size="sm" onClick={onCancel} disabled={flow.canceled}>
              {flow.canceled ? "Cancel requested…" : "Cancel"}
            </Button>
          )}
          {flow.done && <Button variant="ghost" size="icon-sm" aria-label="Close broadcast results" onClick={onClose}><X /></Button>}
        </div>
      </header>
      <div className="scripts-broadcast-results">
        {flow.servers.map((s) => {
          const isExpanded = expanded.has(s.server_id);
          const out = flow.outputs[s.server_id] ?? "";
          return (
            <div key={s.server_id} className={`scripts-broadcast-row ${s.status}`}>
              <button className="scripts-broadcast-row-head" onClick={() => toggle(s.server_id)} aria-expanded={isExpanded}>
                {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                {statusIcon(s)}
                <span className="scripts-broadcast-server">{serverName(s.server_id)}</span>
                <span className={`scripts-broadcast-status ${s.status}`}>{statusLabel(s)}</span>
              </button>
              {isExpanded && (
                <pre className="scripts-broadcast-output" role="log" aria-live="polite" aria-atomic="false" tabIndex={0} aria-label={`Script output for ${serverName(s.server_id)}`}>
                  {out || (s.status === "done" ? "(no output)" : "(no output yet)")}
                  {flow.gaps[s.server_id] && <span className="scripts-gap-warning">output gap</span>}
                </pre>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
