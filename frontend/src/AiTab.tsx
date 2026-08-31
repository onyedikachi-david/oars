import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  ChevronDown,
  KeyRound,
  MessageSquareText,
  RefreshCw,
  Settings2,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import { Bubble } from "./components/ui/bubble";
import { ChatComposer } from "./components/ui/chat-composer";
import { ChatTool, type ChatToolState } from "./components/ui/chat-tool";
import { Message, MessageAvatar, MessageContent } from "./components/ui/message";
import { MessageScroller, MessageScrollerContent } from "./components/ui/message-scroller";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { aiTurnFeedReducer, initialAiTurnFeed } from "./features/ai/reducer";
import { readAiPreviewMode } from "./ai-preview";
import type {
  AiAdapter,
  AiContextGetResult,
  AiCredentialStatus,
  AiExecutionAdmission,
  AiProposal,
  AiProvider,
  AiProviderDraft,
  AiProviderTestOperationState,
  AiThreadSummary,
  AiTurnSnapshot,
  AiTurnState,
  Server,
  SessionStatus,
} from "./types";

function operationId(prefix: string): string {
  return `${prefix}-${globalThis.crypto.randomUUID()}`;
}

function errorMessage(cause: unknown): string {
  return cause instanceof BridgeError ? cause.message : String(cause);
}

const defaultDraft: AiProviderDraft = { name: "", adapter: "openai_responses", tool_mode: "structured_result", base_url: "https://api.openai.com/v1", model: "" };
const terminalTurnStates = new Set<AiTurnState>(["completed", "failed", "canceled", "interrupted", "recovery_required"]);
const promptStarters = [
  "Why is this server low on disk space?",
  "Check the services that need attention.",
  "Explain the recent load and memory pressure.",
] as const;

function providerCredentialStatus(
  provider: AiProvider | null,
  statuses: Record<string, AiCredentialStatus>,
): AiCredentialStatus | "checking" {
  if (!provider) return "missing";
  return Object.prototype.hasOwnProperty.call(statuses, provider.id) ? statuses[provider.id] : "checking";
}

interface ExecutionView extends AiExecutionAdmission {
  cursor: number;
  retainedStart: number;
  output: string;
  dropped: number;
  eof: boolean;
  exit: number | null;
}

function snapshotToolState(turn: AiTurnSnapshot): ChatToolState {
  if (turn.state === "executing" || turn.state === "approved") return "running";
  if (turn.state === "completed") return turn.exit_status !== null && turn.exit_status !== 0 ? "failed" : "completed";
  if (turn.state === "canceled") return "canceled";
  if (turn.state === "interrupted" || turn.state === "recovery_required") return "recovery-required";
  if (turn.state === "failed") return "failed";
  return "approval-requested";
}

export function AiTab({ serverId, onOpenScriptDraft }: { serverId: string; onOpenScriptDraft?: (command: string, destructive: boolean) => void }) {
  const [previewMode] = useState(readAiPreviewMode);
  const mounted = useRef(true);
  const previewThreadOpened = useRef(false);
  const previewProviderTestStarted = useRef(false);
  const turnPollSequence = useRef(0);
  const executionPollSequence = useRef(0);
  const [server, setServer] = useState<Server | null>(null);
  const [sessionStatus, setSessionStatus] = useState<SessionStatus>("closed");
  const [context, setContext] = useState<AiContextGetResult | null>(null);
  const [providers, setProviders] = useState<AiProvider[]>([]);
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [credentialStatuses, setCredentialStatuses] = useState<Record<string, AiCredentialStatus>>({});
  const [credentialBusy, setCredentialBusy] = useState<string | null>(null);
  const [providerTest, setProviderTest] = useState<{ providerId: string; operationId: string; state: AiProviderTestOperationState } | null>(null);
  const [providerTestMessage, setProviderTestMessage] = useState<string | null>(null);
  const [draft, setDraft] = useState<AiProviderDraft>(defaultDraft);
  const [providerSettingsOpen, setProviderSettingsOpen] = useState(false);
  const [threads, setThreads] = useState<AiThreadSummary[]>([]);
  const [conversationTurns, setConversationTurns] = useState<AiTurnSnapshot[]>([]);
  const [pendingMessage, setPendingMessage] = useState<string | null>(null);
  const [retainedExecutions, setRetainedExecutions] = useState<Record<string, ExecutionView>>({});
  const [threadId, setThreadId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [turnId, setTurnId] = useState<string | null>(null);
  const [turnState, setTurnState] = useState<AiTurnState | null>(null);
  const [turnFeed, dispatchTurnFeed] = useReducer(aiTurnFeedReducer, initialAiTurnFeed);
  const [proposal, setProposal] = useState<AiProposal | null>(null);
  const [editCommand, setEditCommand] = useState("");
  const [editing, setEditing] = useState(false);
  const [destructiveAck, setDestructiveAck] = useState(false);
  const [execution, setExecution] = useState<ExecutionView | null>(null);
  const [includeOs, setIncludeOs] = useState(true);
  const [includeMonitor, setIncludeMonitor] = useState(true);
  const [includeLog, setIncludeLog] = useState(() => previewMode === "context-disclosure");
  const [logSource, setLogSource] = useState("");
  const [logTailBytes, setLogTailBytes] = useState(8192);
  const [disclosureAccepted, setDisclosureAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState(false);

  const selectedProvider = useMemo(() => providers.find((item) => item.id === selectedProviderId) ?? null, [providers, selectedProviderId]);
  const selectedThread = useMemo(() => threads.find((item) => item.id === threadId) ?? null, [threads, threadId]);
  const endpointOrigin = useMemo(() => {
    if (!selectedProvider) return "No provider";
    try { return new URL(selectedProvider.base_url).origin; } catch { return selectedProvider.base_url; }
  }, [selectedProvider]);

  const hydrateRetainedExecutions = useCallback(async (turns: AiTurnSnapshot[]) => {
    const retainedTurns = turns.filter((turn) => turn.proposal && turn.execution_id && turn.channel !== null && terminalTurnStates.has(turn.state));
    if (retainedTurns.length === 0) {
      setRetainedExecutions({});
      return;
    }
    try {
      const poll = await api.ssh.poll(serverId, retainedTurns.map((turn) => ({ channel: turn.channel!, cursor: 0 })));
      if (poll.connection_id === null || poll.connection_id === undefined) return setRetainedExecutions({});
      const next: Record<string, ExecutionView> = {};
      for (const turn of retainedTurns) {
        if (turn.connection_id !== poll.connection_id) continue;
        const channel = poll.channels.find((item) => item.id === turn.channel);
        if (!channel) continue;
        const retainedStart = channel.dropped > 0 ? channel.cursor - new TextEncoder().encode(channel.data).length : 0;
        next[turn.id] = {
          ok: true,
          execution_id: turn.execution_id!,
          connection_id: turn.connection_id,
          channel: turn.channel!,
          state: turn.state,
          cursor: channel.cursor,
          retainedStart,
          output: `${channel.dropped > 0 ? `[${channel.dropped} earlier bytes are no longer retained]\n` : ""}${channel.data}`,
          dropped: channel.dropped,
          eof: channel.eof,
          exit: channel.exit ?? turn.exit_status,
        };
      }
      if (mounted.current) setRetainedExecutions(next);
    } catch {
      if (mounted.current) setRetainedExecutions({});
    }
  }, [serverId]);

  const loadThreads = useCallback(async () => {
    try {
      const result = await api.ai.threadList(serverId, 100);
      if (!mounted.current) return;
      setThreads(result.threads);
      setThreadId((current) => current && result.threads.some((item) => item.id === current) ? current : null);
    } catch {
      if (mounted.current) setThreads([]);
    }
  }, [serverId]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [contextResult, providerResult] = await Promise.all([api.ai.contextGet(serverId), api.ai.providerList()]);
      const statuses = await Promise.all(providerResult.providers.map(async (item) => [item.id, (await api.ai.credentialStatus(item.id)).status] as const));
      if (!mounted.current) return;
      setContext(contextResult);
      if (previewMode === "context-disclosure" && contextResult.state === "ready") setLogSource(contextResult.context.active_logs[0]?.path ?? "");
      setProviders(providerResult.providers);
      setCredentialStatuses(Object.fromEntries(statuses));
      setSelectedProviderId((current) => current && providerResult.providers.some((item) => item.id === current) ? current : (providerResult.providers[0]?.id ?? ""));
      void api.servers.list().then((result) => mounted.current && setServer(result.servers.find((item) => item.id === serverId) ?? null)).catch(() => undefined);
      void api.ssh.poll(serverId).then((result) => mounted.current && setSessionStatus(result.status)).catch(() => mounted.current && setSessionStatus("closed"));
      void loadThreads();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [loadThreads, previewMode, serverId]);

  useEffect(() => {
    mounted.current = true;
    void load();
    return () => { mounted.current = false; turnPollSequence.current += 1; executionPollSequence.current += 1; };
  }, [load]);

  useEffect(() => { setDisclosureAccepted(false); }, [includeLog, includeMonitor, includeOs, logSource, logTailBytes, selectedProviderId, serverId]);

  const collectCurrentContext = async () => {
    const id = operationId("context");
    setRefreshing(true);
    try {
      await api.ai.contextRefresh(id, serverId);
      let cursor = 0;
      for (;;) {
        const poll = await api.ai.contextPoll(id, cursor);
        cursor = poll.cursor;
        if (poll.finished) break;
        await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
      }
      const next = await api.ai.contextGet(serverId);
      setContext(next);
      return next;
    } finally { setRefreshing(false); }
  };

  const refreshContext = async () => {
    setError(null);
    try { await collectCurrentContext(); }
    catch (cause) { setError(errorMessage(cause)); }
  };

  const setAdapter = (adapter: AiAdapter) => setDraft((current) => adapter === "openai_responses"
    ? { ...current, adapter, instruction_role: undefined, structured_output: undefined }
    : { ...current, adapter, instruction_role: "system", structured_output: "json_schema" });

  const reloadProviders = async () => {
    const next = (await api.ai.providerList()).providers;
    setProviders(next);
    const statuses = await Promise.all(next.map(async (item) => [item.id, (await api.ai.credentialStatus(item.id)).status] as const));
    setCredentialStatuses(Object.fromEntries(statuses));
  };

  const saveProvider = async () => {
    setError(null);
    try {
      const current = draft.id ? providers.find((item) => item.id === draft.id) : undefined;
      await api.ai.providerSave(operationId("provider"), draft, current?.revision);
      setDraft(defaultDraft);
      setProviderSettingsOpen(false);
      await reloadProviders();
    }
    catch (cause) { setError(errorMessage(cause)); }
  };

  const editProvider = (item: AiProvider) => {
    setDraft({
      id: item.id,
      name: item.name,
      adapter: item.adapter,
      tool_mode: item.tool_mode,
      base_url: item.base_url,
      model: item.model,
      ...(item.instruction_role ? { instruction_role: item.instruction_role } : {}),
      ...(item.structured_output ? { structured_output: item.structured_output } : {}),
    });
    setProviderSettingsOpen(true);
  };

  const deleteProvider = async (item: AiProvider) => {
    setError(null);
    try {
      await api.ai.providerDelete(operationId("provider-delete"), item.id, item.revision);
      if (draft.id === item.id) {
        setDraft(defaultDraft);
        setProviderSettingsOpen(false);
      }
      await reloadProviders();
    } catch (cause) { setError(errorMessage(cause)); }
  };

  const configureCredential = async (item: AiProvider) => {
    setCredentialBusy(item.id); setError(null);
    try {
      const result = await api.ai.credentialConfigure(operationId("credential"), item.id);
      if (result.status !== "canceled") {
        const status: AiCredentialStatus = result.status;
        setCredentialStatuses((current) => ({ ...current, [item.id]: status }));
      }
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setCredentialBusy(null); }
  };

  const deleteCredential = async (item: AiProvider) => {
    setCredentialBusy(item.id); setError(null);
    try {
      const result = await api.ai.credentialDelete(operationId("credential-delete"), item.id);
      setCredentialStatuses((current) => ({ ...current, [item.id]: result.status }));
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setCredentialBusy(null); }
  };

  const testProvider = async (item: AiProvider) => {
    const id = operationId("provider-test");
    setError(null); setProviderTestMessage(null); setProviderTest({ providerId: item.id, operationId: id, state: "queued" });
    try {
      const admission = await api.ai.providerTest(id, item.id, item.revision);
      setProviderTest({ providerId: item.id, operationId: id, state: admission.state });
      let cursor = 0;
      for (;;) {
        const poll = await api.ai.providerTestPoll(id, cursor);
        cursor = poll.cursor;
        setProviderTest({ providerId: item.id, operationId: id, state: poll.state as AiProviderTestOperationState });
        if (poll.finished) {
          const failure = [...poll.events].reverse().find((event) => event.type === "provider.test_failed");
          setProviderTestMessage(failure && "error" in failure.payload ? String(failure.payload.error) : `Provider test ${poll.state}.`);
          break;
        }
        await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
      }
      await reloadProviders();
    } catch (cause) { setError(errorMessage(cause)); setProviderTest(null); }
  };

  const cancelProviderTest = async () => {
    if (!providerTest) return;
    try {
      const result = await api.ai.providerTestCancel(providerTest.operationId);
      setProviderTest((current) => current ? { ...current, state: result.state } : null);
    } catch (cause) { setError(errorMessage(cause)); }
  };

  const openThread = async (id: string | null) => {
    turnPollSequence.current += 1;
    executionPollSequence.current += 1;
    setThreadId(id); setConversationTurns([]); setPendingMessage(null); setRetainedExecutions({}); setProposal(null); dispatchTurnFeed({ type: "reset" }); setExecution(null); setTurnState(null);
    if (!id) return;
    try {
      const detail = await api.ai.threadGet(id);
      setConversationTurns(detail.turns);
      void hydrateRetainedExecutions(detail.turns);
      setProposal(detail.active_proposal);
      if (detail.active_proposal) setEditCommand(detail.active_proposal.command);
      const latest = detail.turns.at(-1);
      dispatchTurnFeed({ type: "snapshot", assistantMessage: latest?.assistant_message ?? null, question: latest?.question ?? null, proposal: detail.active_proposal, status: latest?.state.replaceAll("_", " ") ?? null });
      setTurnId(latest?.id ?? null); setTurnState(latest?.state ?? null);
      if (latest?.execution_id && latest.channel !== null && !terminalTurnStates.has(latest.state)) {
        const admission: AiExecutionAdmission = { ok: true, execution_id: latest.execution_id, connection_id: latest.connection_id, channel: latest.channel, state: latest.state };
        setExecution({ ...admission, cursor: 0, retainedStart: 0, output: "", dropped: 0, eof: false, exit: null });
        void pollExecution(admission, latest.id);
      } else if (latest && !terminalTurnStates.has(latest.state) && latest.state !== "awaiting_approval" && latest.state !== "approved") {
        void pollTurn(latest.id, id);
      }
    } catch (cause) { setError(errorMessage(cause)); }
  };

  useEffect(() => {
    if (previewMode === null || previewThreadOpened.current || threads.length === 0) return;
    previewThreadOpened.current = true;
    void openThread(threads[0].id);
  }, [previewMode, threads]);

  useEffect(() => {
    if (previewProviderTestStarted.current || !selectedProvider) return;
    if (previewMode !== "provider-test-running" && previewMode !== "provider-auth-failed") return;
    if (credentialStatuses[selectedProvider.id] !== "configured") return;
    previewProviderTestStarted.current = true;
    void testProvider(selectedProvider);
  }, [credentialStatuses, previewMode, selectedProvider]);

  const pollTurn = async (id: string, observedThreadId = threadId) => {
    const sequence = ++turnPollSequence.current;
    let cursor = 0;
    for (;;) {
      const poll = await api.ai.turnPoll(id, cursor);
      if (!mounted.current || sequence !== turnPollSequence.current) return;
      cursor = poll.cursor;
      dispatchTurnFeed({ type: "poll", poll });
      const state = poll.state as AiTurnState;
      setTurnState(state);
      if (state === "awaiting_approval" || state === "approved" || state === "executing" || terminalTurnStates.has(state)) break;
      await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
    }
    await loadThreads();
    if (observedThreadId) {
      try {
        const detail = await api.ai.threadGet(observedThreadId);
        if (mounted.current) {
          setConversationTurns(detail.turns);
          setPendingMessage(null);
          void hydrateRetainedExecutions(detail.turns);
        }
      } catch {
        // The live event projection remains authoritative until the next
        // successful durable snapshot refresh.
      }
    }
  };

  const ask = async () => {
    if (!selectedProvider || !message.trim()) return;
    const submittedMessage = message.trim();
    setBusy(true); setError(null); dispatchTurnFeed({ type: "reset" }); dispatchTurnFeed({ type: "status", status: "Preparing current server context" }); setProposal(null); setExecution(null);
    try {
      const currentContext = await collectCurrentContext();
      if (currentContext.state !== "ready" || currentContext.stale) throw new Error("Oars could not collect current server context. Check the connection and try again.");
      dispatchTurnFeed({ type: "status", status: "Queued" });
      const admission = await api.ai.turnStart({
        operation_id: operationId("turn"), ...(threadId ? { thread_id: threadId } : {}), server_id: serverId,
        provider_id: selectedProvider.id, expected_provider_revision: selectedProvider.revision, message: submittedMessage,
        context_selection: { os: includeOs, monitor: includeMonitor, ...(includeLog && logSource ? { log: { source_id: logSource, tail_bytes: logTailBytes } } : {}) },
      });
      setThreadId(admission.thread_id); setTurnId(admission.turn_id); setTurnState(admission.state); setPendingMessage(submittedMessage); setMessage("");
      await pollTurn(admission.turn_id, admission.thread_id);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  };

  const cancelTurn = async () => {
    if (!turnId) return;
    try {
      const result = await api.ai.turnCancel(turnId);
      setTurnState(result.state as AiTurnState);
      dispatchTurnFeed({ type: "status", status: result.state === "cancel_requested" ? "Stop requested; remote termination is being verified." : `Turn ${result.state}.` });
    } catch (cause) { setError(errorMessage(cause)); }
  };

  const editProposal = async () => {
    if (!proposal) return;
    setBusy(true);
    try {
      const result = await api.ai.proposalEdit(operationId("proposal-edit"), proposal.id, proposal.revision, editCommand);
      setProposal(result.proposal); setEditCommand(result.proposal.command); setDestructiveAck(false); setEditing(false);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  };

  const pollExecution = async (admission: AiExecutionAdmission, observedTurnId = turnId) => {
    const sequence = ++executionPollSequence.current;
    let cursor = 0; let outputText = ""; let retainedStart = 0;
    for (;;) {
      const poll = await api.ssh.poll(serverId, [{ channel: admission.channel, cursor }]);
      if (!mounted.current || sequence !== executionPollSequence.current) return;
      setSessionStatus(poll.status);
      if (poll.connection_id !== admission.connection_id) {
        setTurnState("recovery_required");
        setError("The server reconnected during execution. Oars will not attach output from the replacement connection.");
        break;
      }
      const channel = poll.channels.find((item) => item.id === admission.channel);
      if (!channel) {
        if (poll.status !== "ready") { setTurnState("recovery_required"); setError("The connection was lost during execution. Oars will not infer the remote result."); break; }
      } else {
        if (channel.dropped > 0) retainedStart = channel.cursor - new TextEncoder().encode(channel.data).length;
        outputText += channel.data; cursor = channel.cursor;
        setExecution({ ...admission, cursor, retainedStart, output: outputText, dropped: channel.dropped, eof: channel.eof, exit: channel.exit });
        if (channel.eof) break;
      }
      await new Promise((resolve) => globalThis.setTimeout(resolve, 100));
    }
    if (observedTurnId) await pollTurn(observedTurnId);
  };

  const runProposal = async () => {
    if (!proposal) return;
    setBusy(true); setError(null);
    try {
      const admission = await api.ai.proposalRun(operationId("proposal-run"), proposal.id, proposal.revision, proposal.command_sha256, destructiveAck);
      setTurnState(admission.state); setProposal((current) => current ? { ...current, state: "executing" } : current);
      setExecution({ ...admission, cursor: 0, retainedStart: 0, output: "", dropped: 0, eof: false, exit: null });
      void pollExecution(admission);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  };

  const cancelProposal = async () => {
    if (!proposal) return;
    try { await api.ai.proposalCancel(operationId("proposal-cancel"), proposal.id, proposal.revision); setProposal((current) => current ? { ...current, state: "canceled" } : current); setTurnState("canceled"); }
    catch (cause) { setError(errorMessage(cause)); }
  };

  const summarizeOutput = async (selectedExecution: ExecutionView) => {
    if (!threadId || selectedExecution.cursor <= selectedExecution.retainedStart) return;
    setBusy(true);
    try {
      const admission = await api.ai.turnSummarize({ operation_id: operationId("summary"), thread_id: threadId, execution_id: selectedExecution.execution_id, output_selection: { start_cursor: selectedExecution.retainedStart, end_cursor: selectedExecution.cursor } });
      setTurnId(admission.turn_id); setTurnState(admission.state); setProposal(null); dispatchTurnFeed({ type: "reset" }); await pollTurn(admission.turn_id);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setBusy(false); }
  };

  const deleteThread = async () => {
    if (!selectedThread) return;
    try { await api.ai.threadDelete(operationId("thread-delete"), selectedThread.id, selectedThread.revision); await openThread(null); await loadThreads(); }
    catch (cause) { setError(errorMessage(cause)); }
  };

  const selectedLog = context?.state === "ready" ? context.context.active_logs.find((item) => item.path === logSource) : undefined;
  const destructive = Boolean(proposal && (proposal.model_destructive || proposal.local_destructive));
  const credentialStatus = providerCredentialStatus(selectedProvider, credentialStatuses);
  const activeProviderTest = providerTest?.providerId === selectedProvider?.id ? providerTest : null;
  const providerStatus = activeProviderTest?.state ?? selectedProvider?.test_status ?? "not configured";
  const providerReady = selectedProvider?.test_status === "passed" && credentialStatus === "configured";
  const contextReady = context?.state === "ready" && !context.stale;
  const hasContextSelection = includeOs || includeMonitor || (includeLog && Boolean(logSource));
  const workspaceReady = sessionStatus === "ready" && providerReady && disclosureAccepted && hasContextSelection;
  const canAsk = workspaceReady && Boolean(message.trim()) && !busy && !refreshing;
  const contextSelectionSummary = [
    includeOs ? "OS and host" : null,
    includeMonitor ? "monitor snapshot" : null,
    includeLog && selectedLog ? `${selectedLog.path}, at most ${logTailBytes} bytes` : includeLog ? "log source not selected" : "no logs",
  ].filter(Boolean).join(" · ");
  const askBlocker = refreshing ? "Collecting current server context"
    : busy ? "Waiting for Oars"
    : sessionStatus !== "ready" ? "Connect this server first"
    : !selectedProvider ? "Add an AI provider"
    : credentialStatus !== "configured" ? "Configure the provider credential"
    : selectedProvider.test_status !== "passed" ? "Test the provider"
    : includeLog && !logSource ? "Choose a log source or turn off logs"
    : !hasContextSelection ? "Select at least one context source"
    : !disclosureAccepted ? "Review the shared context"
    : !message.trim() ? "Enter a question"
    : null;
  const hasConversationResult = Boolean(turnFeed.assistantMessage || turnFeed.question || proposal || execution || turnFeed.status || turnFeed.error);
  const providerTestActive = Boolean(activeProviderTest && !["passed", "failed", "canceled"].includes(activeProviderTest.state));

  useEffect(() => {
    if (!turnFeed.proposal) return;
    setProposal(turnFeed.proposal);
    setEditCommand(turnFeed.proposal.command);
    setDestructiveAck(false);
  }, [turnFeed.proposal]);

  if (loading && context === null) return <OarsLoadingState title="Preparing AI context" detail="Oars is reading cached context and provider metadata." />;

  const latestSnapshot = conversationTurns.at(-1);
  const liveAssistant = turnFeed.assistantMessage && turnFeed.assistantMessage !== latestSnapshot?.assistant_message ? turnFeed.assistantMessage : null;
  const liveQuestion = turnFeed.question && turnFeed.question !== latestSnapshot?.question ? turnFeed.question : null;
  const hasVisibleAssistantResult = Boolean(liveAssistant || liveQuestion || latestSnapshot?.assistant_message || latestSnapshot?.question || latestSnapshot?.proposal);
  const toolState = turnState === "recovery_required" || turnState === "interrupted" ? "recovery-required" : execution
    ? execution.eof ? (execution.exit === 0 ? "completed" : "failed") : "running"
    : proposal?.state === "canceled" ? "canceled" : "approval-requested";

  return <div className="ai-workspace ai-chat-workspace" aria-labelledby="ai-workspace-title">
    <header className="ai-chat-header">
      <div className="ai-chat-identity">
        <div className="ai-commandbar-icon" aria-hidden="true"><Bot /></div>
        <div><h2 id="ai-workspace-title">Ask about {server?.name ?? serverId}</h2><p>{server ? `${server.user}@${server.host}:${server.port}` : "Server profile unavailable"}</p></div>
      </div>
      <div className="ai-chat-header-actions">
        <span className={`ai-status ${sessionStatus === "ready" ? "is-success" : "is-muted"}`}><i aria-hidden />{sessionStatus === "ready" ? "Connected" : "Disconnected"}</span>
        <Button variant="outline" size="sm" onClick={() => void refreshContext()} disabled={refreshing || busy}>{refreshing ? <RefreshCw className="spin" /> : <RefreshCw />}Refresh context</Button>
      </div>
    </header>

    {(loading || (refreshing && !busy)) && <div className="ai-refresh"><OarsRefreshStatus label={refreshing ? "Collecting current server context" : "Loading AI settings"} /></div>}
    {error && <div className="ai-global-message is-error" role="alert"><AlertTriangle aria-hidden /><div><strong>Oars could not complete that action</strong><span>{error}</span></div></div>}

    <div className="ai-chat-layout">
      <aside className="ai-chat-sidebar" aria-label="Conversation setup">
        <section className="ai-chat-sidebar-block">
          <div className="ai-chat-sidebar-heading"><MessageSquareText /><div><strong>Conversation</strong><span>{threads.length === 0 ? "Saved locally" : `${threads.length} saved locally`}</span></div></div>
          <OarsSelect aria-label="AI conversation" value={threadId ?? "new"} onValueChange={(value) => void openThread(value === "new" ? null : value)} options={[{ value: "new", label: "New conversation" }, ...threads.map((item) => ({ value: item.id, label: item.title }))]} />
          {selectedThread && <Button size="xs" variant="ghost" onClick={() => void deleteThread()} disabled={!terminalTurnStates.has(selectedThread.state)}><Trash2 />Clear conversation</Button>}
        </section>

        <section className="ai-chat-sidebar-block">
          <div className="ai-chat-sidebar-heading"><KeyRound /><div><strong>Provider</strong><span>Native secure store</span></div></div>
          {providers.length > 0 && <OarsSelect aria-label="AI provider" value={selectedProviderId} onValueChange={setSelectedProviderId} options={providers.map((item) => ({ value: item.id, label: `${item.name} · ${item.model}` }))} />}
          {selectedProvider ? <div className="ai-chat-provider">
            <div><strong>{selectedProvider.name}</strong><span>{selectedProvider.model}</span><code title={selectedProvider.base_url}>{endpointOrigin}</code></div>
            <div className="ai-provider-statuses"><span className={`ai-status ${credentialStatus === "configured" ? "is-success" : "is-attention"}`}><i />Credential {credentialStatus}</span><span className={`ai-status ${providerStatus === "passed" ? "is-success" : providerStatus === "failed" ? "is-error" : "is-muted"}`}><i />Test {String(providerStatus).replaceAll("_", " ")}</span></div>
          </div> : <p className="ai-chat-sidebar-copy">Add a provider before you start a conversation.</p>}
          {providerTestMessage && <div className="ai-inline-message" role="status">{providerTestMessage}</div>}
          {selectedProvider && <div className="ai-chat-compact-actions">
            <Button size="sm" variant="outline" onClick={() => void configureCredential(selectedProvider)} disabled={credentialBusy === selectedProvider.id}>{credentialStatus === "configured" ? "Replace credential" : "Configure credential"}</Button>
            {credentialStatus === "configured" && (providerTestActive ? <Button size="sm" variant="outline" onClick={() => void cancelProviderTest()}>Cancel provider test</Button> : <Button size="sm" variant="outline" onClick={() => void testProvider(selectedProvider)}>Test provider · uses quota</Button>)}
          </div>}
          <p className="ai-provider-note">A provider test sends one request and can use provider quota.</p>
          <details className="ai-chat-details" open={providerSettingsOpen} onToggle={(event) => setProviderSettingsOpen(event.currentTarget.open)}><summary role="button" aria-expanded={providerSettingsOpen} aria-controls="ai-provider-settings-form" aria-label={draft.id ? `Edit provider ${draft.name}` : "Manage providers"}><span className="ai-chat-details-icon" aria-hidden><Settings2 /></span><span className="ai-chat-details-copy"><strong>{draft.id ? `Editing ${draft.name}` : "Manage providers"}</strong><small>{draft.id ? "Update this endpoint and model" : "Add or edit an endpoint and model"}</small></span><ChevronDown className="ai-chat-details-chevron" aria-hidden /></summary><div className="ai-provider-form" id="ai-provider-settings-form">
            <label className="ai-form-field"><span>Provider name</span><input aria-label="Provider name" value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></label>
            <label className="ai-form-field"><span>API adapter</span><OarsSelect aria-label="Provider adapter" value={draft.adapter} onValueChange={(value) => setAdapter(value as AiAdapter)} options={[{ value: "openai_responses", label: "OpenAI Responses" }, { value: "openai_chat_completions", label: "Chat Completions" }]} /></label>
            <label className="ai-form-field"><span>Tool capability</span><OarsSelect aria-label="Tool capability" value={draft.tool_mode ?? "structured_result"} onValueChange={(value) => setDraft((current) => ({ ...current, tool_mode: value as "native_function" | "structured_result", ...(value === "native_function" && current.adapter === "openai_chat_completions" ? { structured_output: undefined } : {}) }))} options={[{ value: "native_function", label: "Native function tools" }, { value: "structured_result", label: "Structured result fallback" }]} /></label>
            <label className="ai-form-field"><span>Base URL</span><input aria-label="Provider base URL" value={draft.base_url} onChange={(event) => setDraft((current) => ({ ...current, base_url: event.target.value }))} /></label>
            <label className="ai-form-field"><span>Model</span><input aria-label="Provider model" value={draft.model} onChange={(event) => setDraft((current) => ({ ...current, model: event.target.value }))} /></label>
            {draft.adapter === "openai_chat_completions" && <><label className="ai-form-field"><span>Instruction role</span><OarsSelect aria-label="Instruction role" value={draft.instruction_role ?? "system"} onValueChange={(value) => setDraft((current) => ({ ...current, instruction_role: value as "developer" | "system" }))} options={[{ value: "developer", label: "Developer" }, { value: "system", label: "System" }]} /></label>{(draft.tool_mode ?? "structured_result") === "structured_result" && <label className="ai-form-field"><span>Structured output</span><OarsSelect aria-label="Structured output mode" value={draft.structured_output ?? "json_schema"} onValueChange={(value) => setDraft((current) => ({ ...current, structured_output: value as "json_schema" | "json_object" }))} options={[{ value: "json_schema", label: "JSON Schema" }, { value: "json_object", label: "JSON object" }]} /></label>}</>}
            <div className="ai-chat-compact-actions"><Button size="sm" onClick={() => void saveProvider()} disabled={!draft.name.trim() || !draft.model.trim()}>Save provider</Button>{draft.id && <Button size="sm" variant="ghost" onClick={() => { setDraft(defaultDraft); setProviderSettingsOpen(false); }}>Cancel</Button>}</div>
            {selectedProvider && <div className="ai-provider-secondary-actions"><Button size="xs" variant="ghost" onClick={() => editProvider(selectedProvider)}><Settings2 />Edit selected</Button>{credentialStatus === "configured" && <Button size="xs" variant="ghost" onClick={() => void deleteCredential(selectedProvider)}>Remove credential</Button>}<Button className="ai-danger-action" size="xs" variant="ghost" onClick={() => void deleteProvider(selectedProvider)}><Trash2 />Delete</Button></div>}
          </div></details>
        </section>

        <section className="ai-chat-sidebar-block" id="ai-context-settings">
          <div className="ai-chat-sidebar-heading"><ShieldCheck /><div><strong>Shared context</strong><span>Review what leaves this Mac</span></div></div>
          <p className="ai-chat-sidebar-copy">Current host, process, log, and user text is treated as untrusted data.</p>
          <div className="ai-context-options">
            <label className={includeOs ? "is-selected" : ""}><input type="checkbox" checked={includeOs} onChange={(event) => setIncludeOs(event.target.checked)} /><span><strong>OS and host</strong><small>Release, hostname, and host facts</small></span></label>
            <label className={includeMonitor ? "is-selected" : ""}><input type="checkbox" checked={includeMonitor} onChange={(event) => setIncludeMonitor(event.target.checked)} /><span><strong>Monitor snapshot</strong><small>CPU, memory, disk, and processes</small></span></label>
            <label className={includeLog ? "is-selected" : ""}><input type="checkbox" checked={includeLog} onChange={(event) => setIncludeLog(event.target.checked)} /><span><strong>One log tail</strong><small>One source with a byte limit</small></span></label>
          </div>
          {includeLog && <div className="ai-log-fields"><label className="ai-form-field"><span>Log source</span><OarsSelect aria-label="Log source" value={logSource} onValueChange={setLogSource} options={(context?.state === "ready" ? context.context.active_logs : []).map((item) => ({ value: item.path, label: item.path }))} placeholder="Select a log" /></label><label className="ai-form-field"><span>Maximum tail</span><OarsSelect aria-label="Log tail bytes" value={String(logTailBytes)} onValueChange={(value) => setLogTailBytes(Number(value))} options={[4096, 8192, 16384, 32768, 65536].map((bytes) => ({ value: String(bytes), label: `${bytes / 1024} KiB` }))} /></label></div>}
          <label className={`ai-context-approval ${disclosureAccepted ? "is-selected" : ""}`}><input aria-label="I reviewed this exact selection" type="checkbox" checked={disclosureAccepted} onChange={(event) => setDisclosureAccepted(event.target.checked)} /><span><strong>{disclosureAccepted ? "Context reviewed" : "Review this selection"}</strong><small>Oars collects current values when you send.</small></span></label>
        </section>
      </aside>

      <main className="ai-chat-main">
        <MessageScroller follow>
          <MessageScrollerContent>
            {conversationTurns.length === 0 && !hasConversationResult && <section className="ai-chat-empty">
              <div className="ai-empty-icon"><Bot /></div><h3>What should we investigate?</h3><p>Ask about this server. If Oars needs a command, you will review the exact target and command here before anything runs.</p>
              <div className="ai-prompt-starters">{promptStarters.map((prompt) => <button key={prompt} type="button" onClick={() => setMessage(prompt)}>{prompt}</button>)}</div>
            </section>}

            {conversationTurns.map((turn) => <div className="ai-chat-turn" key={turn.id}>
              <Message className="is-user"><MessageContent><Bubble role="user">{turn.message}</Bubble></MessageContent></Message>
              {turn.assistant_message && <Message className="is-assistant"><MessageAvatar><Bot /></MessageAvatar><MessageContent><Bubble role="assistant">{turn.assistant_message}</Bubble></MessageContent></Message>}
              {turn.question && <Message className="is-assistant"><MessageAvatar><Bot /></MessageAvatar><MessageContent><Bubble role="assistant"><strong>I need one detail</strong><span>{turn.question}</span></Bubble></MessageContent></Message>}
              {turn.proposal && turn.proposal.id !== proposal?.id && <Message className="is-assistant is-tool"><MessageAvatar><Bot /></MessageAvatar><MessageContent><ChatTool
                title="Run server command" target={`${server?.user ?? "user"}@${server?.host ?? turn.proposal.server_id}`} command={turn.proposal.command} explanation={turn.proposal.explanation}
                state={snapshotToolState(turn)} destructive={turn.proposal.model_destructive || turn.proposal.local_destructive}
                output={turn.execution_id ? retainedExecutions[turn.id]?.output ?? "" : undefined} exit={retainedExecutions[turn.id]?.exit ?? turn.exit_status}
                onSummarize={snapshotToolState(turn) === "completed" && retainedExecutions[turn.id]?.cursor > retainedExecutions[turn.id]?.retainedStart ? () => void summarizeOutput(retainedExecutions[turn.id]) : undefined}
                extraActions={onOpenScriptDraft ? <Button size="sm" variant="ghost" onClick={() => onOpenScriptDraft(turn.proposal!.command, turn.proposal!.model_destructive || turn.proposal!.local_destructive)}>Open in Scripts</Button> : null}
              /></MessageContent></Message>}
            </div>)}

            {pendingMessage && <Message className="is-user"><MessageContent><Bubble role="user">{pendingMessage}</Bubble></MessageContent></Message>}
            {liveAssistant && <Message className="is-assistant"><MessageAvatar><Bot /></MessageAvatar><MessageContent><Bubble role="assistant">{liveAssistant}</Bubble></MessageContent></Message>}
            {liveQuestion && <Message className="is-assistant"><MessageAvatar><Bot /></MessageAvatar><MessageContent><Bubble role="assistant"><strong>I need one detail</strong><span>{liveQuestion}</span></Bubble></MessageContent></Message>}

            {proposal && <Message className="is-assistant is-tool"><MessageAvatar><Bot /></MessageAvatar><MessageContent><ChatTool
              title="Run server command" target={`${server?.user ?? "user"}@${server?.host ?? proposal.server_id}`} command={proposal.command} explanation={proposal.explanation}
              state={toolState} destructive={destructive} output={execution?.output} exit={execution?.exit} editing={editing} editCommand={editCommand} destructiveAck={destructiveAck} busy={busy}
              onEditCommand={setEditCommand} onStartEdit={() => setEditing(true)} onSaveEdit={() => void editProposal()} onCancelEdit={() => { setEditing(false); setEditCommand(proposal.command); }} onAckChange={setDestructiveAck}
              onRun={() => void runProposal()} onCancel={() => void cancelProposal()} onSummarize={execution?.eof && execution.cursor > execution.retainedStart ? () => void summarizeOutput(execution) : undefined}
              extraActions={onOpenScriptDraft && !execution ? <Button size="sm" variant="ghost" onClick={() => onOpenScriptDraft(proposal.command, destructive)}>Open in Scripts</Button> : null}
            /></MessageContent></Message>}

            {(turnFeed.status || turnFeed.error || turnState) && !hasVisibleAssistantResult && !proposal && <div className={`ai-chat-activity ${turnFeed.error ? "is-error" : ""}`} role={turnFeed.error ? "alert" : "status"}><span className="ai-state-pulse" />{turnFeed.error ?? (turnState ? turnState.replaceAll("_", " ") : turnFeed.status)}</div>}
          </MessageScrollerContent>
        </MessageScroller>

        <ChatComposer value={message} onChange={setMessage} onSend={() => void ask()} onStop={turnId && turnState && !terminalTurnStates.has(turnState) && turnState !== "awaiting_approval" ? () => void cancelTurn() : undefined}
          disabled={!canAsk} busy={busy} blocker={askBlocker} contextSummary={contextSelectionSummary} onOpenContext={() => document.getElementById("ai-context-settings")?.scrollIntoView({ behavior: "smooth", block: "center" })} />
      </main>
    </div>
  </div>;
}
