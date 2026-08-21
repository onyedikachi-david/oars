import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Download,
  FileText,
  FileWarning,
  Lock,
  Pause,
  Play,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { api, BridgeError, pickSaveFile } from "./bridge";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState } from "./components/OarsLoadingState";
import { ApplicationNotice, ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import { isCurrentLogRequest, nextLogCursor, type LogRequestToken } from "./log-view-state";
import {
  ageLabel,
  sizeLabel,
  modeLabel,
  formatMtime,
  GROUP_ORDER,
  GROUP_LABEL,
  LINE_COUNTS,
  type LineCount,
  FOLLOW_MAX_CHARS,
  LINE_RENDER_CAP,
} from "./logs-state";
import type { LogSource, Server } from "./types";

// ── Helpers ────────────────────────────────────────────────────────────────

function messageOf(error: unknown): string {
  return error instanceof BridgeError ? error.message : String(error);
}

// ── State machines ─────────────────────────────────────────────────────────

type ScanStatus = "idle" | "scanning" | "ready" | "error";
type ReadStatus = "idle" | "loading" | "ready" | "binary" | "error" | "unreadable";
type FollowStatus = "off" | "starting" | "live" | "eof" | "error";
type DownloadStatus = "idle" | "starting" | "running" | "done" | "failed" | "canceled";

interface ScanState {
  status: ScanStatus;
  sources: LogSource[];
  partial: boolean;
  reason: string;
  error: string | null;
}

interface ReadState {
  status: ReadStatus;
  sourcePath: string | null;
  lines: string[];
  limited: boolean;
  error: string | null;
}

interface FollowState {
  status: FollowStatus;
  channel: number | null;
  cursor: number;
  dropped: number;
  error: string | null;
}

interface DownloadState {
  status: DownloadStatus;
  opId: number | null;
  bytes: number;
  total: number;
  localPath: string | null;
  error: string | null;
}
const FOLLOW_POLL_MS = 300;
const DOWNLOAD_POLL_MS = 300;
// The backend's identity-bound clear refuses with exactly this message when
// the file changed since the preview (sessions.zig clearLogFile).
const CLEAR_CONFLICT_TEXT = "file changed since preview";

const emptyScan: ScanState = { status: "idle", sources: [], partial: false, reason: "", error: null };
const emptyRead: ReadState = { status: "idle", sourcePath: null, lines: [], limited: false, error: null };
const emptyFollow: FollowState = { status: "off", channel: null, cursor: 0, dropped: 0, error: null };
const idleDownload: DownloadState = { status: "idle", opId: null, bytes: 0, total: 0, localPath: null, error: null };

export function LogsTab({ server }: { server: Server }) {
  const serverId = server.id;

  const [scan, setScan] = useState<ScanState>(emptyScan);
  const [selected, setSelected] = useState<string | null>(null);
  const [lineCount, setLineCount] = useState<LineCount>(200);
  const [read, setRead] = useState<ReadState>(emptyRead);
  const [follow, setFollow] = useState<FollowState>(emptyFollow);
  const [followData, setFollowData] = useState("");
  const [followTrimmed, setFollowTrimmed] = useState(false);
  const [sourceQuery, setSourceQuery] = useState("");
  const [viewerQuery, setViewerQuery] = useState("");
  const [manualPath, setManualPath] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [clearTarget, setClearTarget] = useState<LogSource | null>(null);
  const [clearBusy, setClearBusy] = useState(false);
  const [clearError, setClearError] = useState<string | null>(null);
  const [clearResult, setClearResult] = useState<{ before: number; after: number } | null>(null);
  const [download, setDownload] = useState<DownloadState>(idleDownload);
  const [notice, setNotice] = useState<string | null>(null);
  const [stickToLatest, setStickToLatest] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const mountedRef = useRef(true);
  const selectedRef = useRef<string | null>(selected);
  selectedRef.current = selected;
  const scanGenRef = useRef(0);
  const readGenRef = useRef(0);
  const followGenRef = useRef(0);
  const followRef = useRef<{ channel: number; cursor: number } | null>(null);
  const followPollingRef = useRef(false);
  const followTimerRef = useRef<number | null>(null);
  const followDataRef = useRef("");
  const stickRef = useRef(true);
  const bodyRef = useRef<HTMLDivElement>(null);
  const downloadOpRef = useRef<number | null>(null);
  const downloadPollingRef = useRef(false);
  const downloadTimerRef = useRef<number | null>(null);
  const downloadLocalRef = useRef<string | null>(null);
  const noticeTimerRef = useRef<number | null>(null);

  const followActive = follow.status === "starting" || follow.status === "live" || follow.status === "eof";
  const followRunning = follow.status === "starting" || follow.status === "live";

  const showNotice = useCallback((text: string) => {
    setNotice(text);
    if (noticeTimerRef.current) window.clearTimeout(noticeTimerRef.current);
    noticeTimerRef.current = window.setTimeout(() => setNotice(null), 3200);
  }, []);

  // ── Derived view state ───────────────────────────────────────────────────

  const filteredSources = useMemo(() => {
    const q = sourceQuery.trim().toLowerCase();
    if (!q) return scan.sources;
    return scan.sources.filter(
      (s) => s.path.toLowerCase().includes(q) || s.name.toLowerCase().includes(q),
    );
  }, [scan.sources, sourceQuery]);

  const grouped = useMemo(() => {
    const byGroup = new Map<string, LogSource[]>();
    for (const s of filteredSources) {
      const g = GROUP_LABEL[s.group] ? s.group : "custom";
      const list = byGroup.get(g) ?? [];
      list.push(s);
      byGroup.set(g, list);
    }
    return GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({
      group: g,
      label: GROUP_LABEL[g],
      items: byGroup.get(g)!,
    }));
  }, [filteredSources]);

  const allVisibleSources = useMemo(
    () => grouped.flatMap((g) => g.items),
    [grouped]
  );
  const [focusedSourceIndex, setFocusedSourceIndex] = useState(0);

  useEffect(() => {
    setFocusedSourceIndex((prev) => {
      if (allVisibleSources.length === 0) return 0;
      if (prev >= allVisibleSources.length) return allVisibleSources.length - 1;
      return prev;
    });
  }, [allVisibleSources.length]);

  const handleSourceRowKeyDown = (event: React.KeyboardEvent, sourcePath: string, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(allVisibleSources.length - 1, index + 1);
      setFocusedSourceIndex(next);
      const btns = document.querySelectorAll<HTMLButtonElement>(".logs-groups .logs-source");
      btns[next]?.focus();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedSourceIndex(prev);
      const btns = document.querySelectorAll<HTMLButtonElement>(".logs-groups .logs-source");
      btns[prev]?.focus();
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setFocusedSourceIndex(0);
      const btns = document.querySelectorAll<HTMLButtonElement>(".logs-groups .logs-source");
      btns[0]?.focus();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      const last = allVisibleSources.length - 1;
      setFocusedSourceIndex(last);
      const btns = document.querySelectorAll<HTMLButtonElement>(".logs-groups .logs-source");
      btns[last]?.focus();
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectSource(sourcePath);
      return;
    }
  };

  const selectedSource = useMemo(
    () => scan.sources.find((s) => s.path === selected) ?? null,
    [scan.sources, selected],
  );

  const displayLines = useMemo(() => {
    if (followActive) {
      if (followData.length === 0) return [];
      const parts = followData.split("\n");
      // A trailing newline is a line terminator, not an empty line.
      if (parts.length > 1 && parts[parts.length - 1] === "") parts.pop();
      return parts;
    }
    return read.sourcePath === selected ? read.lines : [];
  }, [followActive, followData, read.lines, read.sourcePath, selected]);

  const getLineKey = useCallback(
    (index: number) => `${serverId}:${selected ?? "none"}:${followActive ? "follow" : lineCount}:${index}`,
    [followActive, lineCount, selected, serverId],
  );
  const lineVirtualizer = useVirtualizer({
    count: displayLines.length,
    getScrollElement: () => bodyRef.current,
    estimateSize: () => 17,
    getItemKey: getLineKey,
    overscan: 20,
    // TanStack recommends this for React 19 to avoid lifecycle flushSync warnings.
    useFlushSync: false,
  });
  const binarySelected = read.sourcePath === selected && read.status === "binary";

  // ── Scan ─────────────────────────────────────────────────────────────────

  const runScan = useCallback(async (): Promise<LogSource[] | null> => {
    const gen = ++scanGenRef.current;
    setScan((prev) => ({ ...prev, status: "scanning", error: null }));
    try {
      const r = await api.logs.scan(serverId);
      if (!mountedRef.current || gen !== scanGenRef.current) return null;
      setScan({ status: "ready", sources: r.sources, partial: r.partial, reason: r.reason, error: null });
      setSelected((prev) => {
        if (prev && r.sources.some((s) => s.path === prev)) return prev;
        const first = r.sources.find((s) => s.readable) ?? r.sources[0];
        return first ? first.path : null;
      });
      return r.sources;
    } catch (e) {
      if (mountedRef.current && gen === scanGenRef.current) {
        setScan((prev) => ({ ...prev, status: "error", error: messageOf(e) }));
      }
      return null;
    }
  }, [serverId]);

  // Mount/server-change lifecycle: scan once, and close the owned follow
  // channel on every exit path (unmount or a different server tab).
  useEffect(() => {
    mountedRef.current = true;
    void runScan();
    return () => {
      mountedRef.current = false;
      readGenRef.current += 1;
      followGenRef.current += 1;
      const ch = followRef.current;
      followRef.current = null;
      if (followTimerRef.current) window.clearTimeout(followTimerRef.current);
      if (downloadTimerRef.current) window.clearTimeout(downloadTimerRef.current);
      if (noticeTimerRef.current) window.clearTimeout(noticeTimerRef.current);
      if (ch) void api.ssh.closeChannel(serverId, ch.channel).catch(() => {});
    };
  }, [serverId, runScan]);

  // ── Read ─────────────────────────────────────────────────────────────────

  // The token is created before every branch so an unreadable or empty source
  // also invalidates any older in-flight read.
  useEffect(() => {
    const token: LogRequestToken = {
      generation: ++readGenRef.current,
      serverId,
      path: selected,
    };
    if (!selected) {
      setRead(emptyRead);
      return;
    }
    if (selectedSource && !selectedSource.readable) {
      // The scan probe already proved this source is unreadable: show the
      // reason instead of running a read that must fail.
      setRead({ status: "unreadable", sourcePath: selected, lines: [], limited: false, error: null });
      return;
    }
    setRead((prev) => prev.sourcePath === selected
      ? { ...prev, status: "loading", error: null }
      : { status: "loading", sourcePath: selected, lines: [], limited: false, error: null });
    void (async () => {
      try {
        const r = await api.logs.read(serverId, selected, lineCount);
        if (!mountedRef.current || !isCurrentLogRequest(
          token,
          readGenRef.current,
          serverId,
          selectedRef.current,
        )) return;
        setRead({
          status: r.binary ? "binary" : "ready",
          sourcePath: selected,
          lines: r.binary ? [] : r.lines,
          limited: r.limited,
          error: null,
        });
      } catch (e) {
        if (!mountedRef.current || !isCurrentLogRequest(
          token,
          readGenRef.current,
          serverId,
          selectedRef.current,
        )) return;
        setRead({ status: "error", sourcePath: selected, lines: [], limited: false, error: messageOf(e) });
      }
    })();
  }, [serverId, selected, lineCount, reloadTick, selectedSource]);

  // ── Follow ───────────────────────────────────────────────────────────────

  // Releases the follow channel: one channel, one absolute cursor, closed on
  // every exit path (user stop, source switch, EOF, error, unmount).
  const teardownFollow = useCallback((next: FollowStatus, error: string | null = null) => {
    followGenRef.current += 1;
    const ch = followRef.current;
    followRef.current = null;
    if (followTimerRef.current) {
      window.clearTimeout(followTimerRef.current);
      followTimerRef.current = null;
    }
    if (mountedRef.current) {
      setFollow((prev) => ({ ...prev, status: next, channel: null, error }));
    }
    if (!ch) return Promise.resolve();
    return api.ssh.closeChannel(serverId, ch.channel).catch(() => {
      // Best effort: the backend tolerates unknown channels.
    });
  }, [serverId]);

  // Auto-scroll must run after the appended data commits, or scrollTop
  // lands against the stale scrollHeight and drifts away from the true
  // bottom (visible as a growing gap while following).
  useEffect(() => {
    if (followActive && stickRef.current && bodyRef.current) {
      const last = displayLines.length - 1;
      if (last >= 0) lineVirtualizer.scrollToIndex(last, { align: "end" });
    }
  }, [displayLines.length, followActive, followData, lineVirtualizer]);

  const pollFollow = useCallback(async () => {
    const ch = followRef.current;
    if (!ch || !mountedRef.current) return;
    if (followPollingRef.current) return; // never overlap polls
    followPollingRef.current = true;
    try {
      const result = await api.ssh.poll(serverId, [{ channel: ch.channel, cursor: ch.cursor }], false);
      if (!mountedRef.current || followRef.current !== ch) return;
      const current = result.channels.find((entry) => entry.id === ch.channel);
      if (!current) {
        // The channel vanished (session teardown): follow is over.
        void teardownFollow("eof");
        return;
      }
      ch.cursor = nextLogCursor(current.cursor);
      setFollow((prev) => ({
        ...prev,
        cursor: ch.cursor,
        dropped: current.dropped > 0 ? Math.max(prev.dropped, current.dropped) : prev.dropped,
      }));
      if (current.data) {
        const combined = followDataRef.current + current.data;
        if (combined.length > FOLLOW_MAX_CHARS) {
          setFollowTrimmed(true);
        }
        followDataRef.current = combined.slice(-FOLLOW_MAX_CHARS);
        setFollowData(followDataRef.current);
      }
      if (current.eof) {
        // tail exited: the source stopped or disappeared (spec 04 §10).
        void teardownFollow("eof");
        return;
      }
      followTimerRef.current = window.setTimeout(() => void pollFollow(), FOLLOW_POLL_MS);
    } catch (e) {
      if (mountedRef.current && followRef.current === ch) {
        void teardownFollow("error", messageOf(e));
      }
    } finally {
      followPollingRef.current = false;
    }
  }, [serverId, teardownFollow]);

  const startFollow = useCallback(async () => {
    if (!selected || followRef.current || followRunning || read.status !== "ready" || binarySelected) return;
    const token: LogRequestToken = {
      generation: ++followGenRef.current,
      serverId,
      path: selected,
    };
    setFollow({ status: "starting", channel: null, cursor: 0, dropped: 0, error: null });
    try {
      const r = await api.logs.follow(serverId, selected);
      if (!mountedRef.current || !isCurrentLogRequest(
        token,
        followGenRef.current,
        serverId,
        selectedRef.current,
      )) {
        void api.ssh.closeChannel(serverId, r.channel).catch(() => {});
        return;
      }
      followRef.current = { channel: r.channel, cursor: 0 };
      followDataRef.current = "";
      setFollowTrimmed(false);
      setFollowData("");
      setFollow({ status: "live", channel: r.channel, cursor: 0, dropped: 0, error: null });
      stickRef.current = true;
      setStickToLatest(false);
      void pollFollow();
    } catch (e) {
      if (mountedRef.current && isCurrentLogRequest(
        token,
        followGenRef.current,
        serverId,
        selectedRef.current,
      )) {
        setFollow({ status: "error", channel: null, cursor: 0, dropped: 0, error: messageOf(e) });
      }
    }
  }, [binarySelected, followRunning, pollFollow, read.status, selected, serverId]);

  const toggleFollow = () => {
    if (followRunning) {
      void teardownFollow("off");
      // Restore a static read view at the chosen history depth.
      setReloadTick((t) => t + 1);
    } else {
      void startFollow();
    }
  };

  const changeLineCount = (next: LineCount) => {
    if (follow.status === "eof" || follow.status === "error") {
      void teardownFollow("off");
      followDataRef.current = "";
      setFollowData("");
      setFollowTrimmed(false);
    }
    setLineCount(next);
  };

  const selectSource = (path: string) => {
    if (!path || path === selected) return;
    selectedRef.current = path;
    if (follow.status !== "off") void teardownFollow("off");
    followDataRef.current = "";
    setFollowData("");
    setFollowTrimmed(false);
    stickRef.current = true;
    setStickToLatest(false);
    setSelected(path);
  };

  const handleBodyScroll = () => {
    const body = bodyRef.current;
    if (!body) return;
    const nearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 48;
    stickRef.current = nearBottom;
    setStickToLatest(!nearBottom);
  };

  const jumpToLatest = () => {
    stickRef.current = true;
    setStickToLatest(false);
    const last = displayLines.length - 1;
    if (last >= 0) lineVirtualizer.scrollToIndex(last, { align: "end" });
  };

  // ── Clear (identity-bound truncate) ──────────────────────────────────────

  const openClear = (source: LogSource) => {
    setClearTarget(source);
    setClearError(null);
    setClearResult(null);
  };

  const closeClear = () => {
    if (clearBusy) return;
    setClearTarget(null);
    setClearError(null);
    setClearResult(null);
  };

  const confirmClear = async () => {
    if (!clearTarget) return;
    const source = clearTarget;
    setClearBusy(true);
    setClearError(null);
    setClearResult(null);
    try {
      // The preview is passed through unchanged: size, mtime, and mode from
      // the selected LogSource. A stale preview is refused by the backend.
      const r = await api.logs.clear(serverId, source.path, {
        size: source.size,
        mtime: source.mtime_epoch,
        mode: source.mode,
      });
      if (!mountedRef.current) return;
      setClearResult({ before: r.before_size, after: r.after_size });
      setReloadTick((t) => t + 1);
      // The backend invalidated the scan cache, so this rescan serves fresh
      // sizes and stamps.
      void runScan();
    } catch (e) {
      if (mountedRef.current) setClearError(messageOf(e));
    } finally {
      if (mountedRef.current) setClearBusy(false);
    }
  };

  // A stale preview must not be retried: rescan for a fresh identity, then
  // require a new confirmation from the user.
  const rescanForClear = async () => {
    if (!clearTarget) return;
    setClearError(null);
    const sources = await runScan();
    if (!mountedRef.current) return;
    const fresh = sources?.find((s) => s.path === clearTarget.path);
    if (fresh) {
      setClearTarget(fresh);
    } else {
      setClearError("The source no longer appears in the scan. Close this dialog and scan again.");
    }
  };

  const clearIsConflict = clearError !== null && clearError.includes(CLEAR_CONFLICT_TEXT);

  // ── Download through SFTP ────────────────────────────────────────────────

  const pollDownload = useCallback(async () => {
    const opId = downloadOpRef.current;
    if (opId === null || !mountedRef.current) return;
    if (downloadPollingRef.current) return;
    downloadPollingRef.current = true;
    try {
      const r = await api.sftp.poll(serverId);
      if (!mountedRef.current) return;
      const t = r.transfers.find((x) => x.id === opId);
      if (!t) {
        downloadOpRef.current = null;
        setDownload((prev) => ({ ...prev, status: "failed", error: "The transfer record disappeared from the server session." }));
        return;
      }
      setDownload((prev) => ({ ...prev, bytes: t.bytes, total: t.total }));
      if (t.status === "done") {
        downloadOpRef.current = null;
        setDownload((prev) => ({ ...prev, status: "done", bytes: t.bytes, total: t.total }));
        showNotice(`Downloaded ${sizeLabel(t.bytes)} to ${downloadLocalRef.current ?? "the chosen location"}.`);
        return;
      }
      if (t.status === "failed") {
        downloadOpRef.current = null;
        setDownload((prev) => ({ ...prev, status: "failed", error: t.error || "The download failed." }));
        return;
      }
      if (t.status === "canceled") {
        downloadOpRef.current = null;
        setDownload((prev) => ({ ...prev, status: "canceled" }));
        return;
      }
      downloadTimerRef.current = window.setTimeout(() => void pollDownload(), DOWNLOAD_POLL_MS);
    } catch (e) {
      if (mountedRef.current) {
        downloadOpRef.current = null;
        setDownload((prev) => ({ ...prev, status: "failed", error: messageOf(e) }));
      }
    } finally {
      downloadPollingRef.current = false;
    }
  }, [serverId, showNotice]);

  const startDownload = async () => {
    if (!selected || download.status === "starting" || download.status === "running") return;
    const name = selected.split("/").pop() || "log";
    let localPath: string | null = null;
    try {
      localPath = await pickSaveFile(`Save ${name}`, name);
    } catch (e) {
      setDownload({ ...idleDownload, status: "failed", error: messageOf(e) });
      return;
    }
    if (!localPath) return; // dialog canceled — nothing started
    downloadLocalRef.current = localPath;
    setDownload({ status: "starting", opId: null, bytes: 0, total: 0, localPath, error: null });
    try {
      const r = await api.sftp.download(serverId, { utf8: selected }, localPath);
      if (!mountedRef.current) return;
      downloadOpRef.current = r.op_id;
      setDownload({ status: "running", opId: r.op_id, bytes: 0, total: 0, localPath, error: null });
      void pollDownload();
    } catch (e) {
      if (mountedRef.current) {
        downloadOpRef.current = null;
        setDownload({ status: "failed", opId: null, bytes: 0, total: 0, localPath, error: messageOf(e) });
      }
    }
  };

  const cancelDownload = async () => {
    const opId = downloadOpRef.current;
    if (opId === null) return;
    try {
      await api.sftp.cancel(serverId, opId);
    } catch {
      // The poll loop surfaces the failure honestly if cancel cannot queue.
    }
  };

  const dismissDownload = () => {
    downloadOpRef.current = null;
    if (downloadTimerRef.current) window.clearTimeout(downloadTimerRef.current);
    setDownload(idleDownload);
  };

  // ── Add source ───────────────────────────────────────────────────────────

  const addSource = async () => {
    const path = manualPath.trim();
    if (!path || adding) return;
    setAdding(true);
    setAddError(null);
    try {
      await api.logs.addSource(serverId, path);
      setManualPath("");
      const sources = await runScan();
      if (sources?.some((s) => s.path === path)) selectSource(path);
      showNotice(`Added ${path} as a log source.`);
    } catch (e) {
      setAddError(messageOf(e));
    } finally {
      if (mountedRef.current) setAdding(false);
    }
  };

  const viewerMatches = useMemo(() => {
    const q = viewerQuery.trim().toLowerCase();
    if (!q) return null;
    let count = 0;
    for (const line of displayLines) {
      const lower = line.toLowerCase();
      let from = 0;
      while (true) {
        const at = lower.indexOf(q, from);
        if (at === -1) break;
        count += 1;
        from = at + q.length;
      }
    }
    return count;
  }, [displayLines, viewerQuery]);

  const renderLineContent = useCallback(
    (line: string) => {
      const capped = line.length > LINE_RENDER_CAP ? line.slice(0, LINE_RENDER_CAP) : line;
      const q = viewerQuery.trim().toLowerCase();
      const content: React.ReactNode[] = [];
      if (!q) {
        content.push(capped);
      } else {
        const lower = capped.toLowerCase();
        let from = 0;
        let hit = 0;
        while (true) {
          const at = lower.indexOf(q, from);
          if (at === -1) {
            content.push(capped.slice(from));
            break;
          }
          if (at > from) content.push(capped.slice(from, at));
          content.push(
            <mark key={hit} className="logs-hit">
              {capped.slice(at, at + q.length)}
            </mark>,
          );
          hit += 1;
          from = at + q.length;
        }
      }
      return (
        <>
          {content}
          {line.length > LINE_RENDER_CAP && <span className="logs-line-truncated">… line truncated</span>}
        </>
      );
    },
    [viewerQuery],
  );

  const downloadPercent =
    download.status === "running" && download.total > 0
      ? Math.min(100, Math.round((download.bytes / download.total) * 100))
      : 0;

  // ── Render ───────────────────────────────────────────────────────────────

  if (scan.status === "scanning" && scan.sources.length === 0) {
    return (
      <section className="logs" aria-label="Log viewer">
        <OarsLoadingState
          title="Finding server logs"
          detail={`Oars is checking the documented log locations on ${server.name}.`}
        />
      </section>
    );
  }

  return (
    <section className="logs" aria-label="Log viewer">
      <header className="logs-overview">
        <div>
          <div className="monitor-kicker"><FileText size={15} /> Log viewer</div>
          <div className="monitor-title-row">
            <h2>Server logs</h2>
            <span className="logs-health">
              <span className="monitor-state-dot" aria-hidden />
              {scan.status === "scanning"
                ? "Scanning"
                : scan.status === "error"
                  ? "Scan failed"
                  : scan.partial
                    ? "Partial scan"
                    : `${scan.sources.length} source${scan.sources.length === 1 ? "" : "s"}`}
            </span>
          </div>
          <p>
            {server.name} · {server.user}@{server.host}:{server.port} ·{" "}
            {scan.status === "ready" ? "Scan cached for 60 seconds" : "Reading documented log locations"}
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => void runScan()}
          disabled={scan.status === "scanning"}
          aria-label="Re-scan log sources"
        >
          <RefreshCw className={scan.status === "scanning" ? "spin" : ""} />
          {scan.status === "scanning" ? "Scanning…" : "Re-scan"}
        </Button>
      </header>

      {scan.status === "error" && (
        <div className="logs-banner logs-banner-error" role="alert">
          <AlertTriangle />
          <div><strong>Log scan failed</strong><span>{scan.error}</span></div>
        </div>
      )}
      {scan.status === "ready" && scan.partial && (
        <div className="logs-banner logs-banner-warn" role="status">
          <AlertTriangle />
          <div><strong>Scan was cut short</strong><span>{scan.reason}</span></div>
        </div>
      )}
      {notice && <ApplicationNotice><div className="logs-toast" role="status">{notice}</div></ApplicationNotice>}

      <div className="logs-mobile-source">
        <label htmlFor="logs-mobile-select">Active log</label>
        <OarsSelect
          id="logs-mobile-select"
          value={selected ?? ""}
          onValueChange={(sourcePath) => { if (sourcePath) selectSource(sourcePath); }}
          placeholder="Select a log source…"
          options={scan.sources.map((source) => ({ value: source.path, label: `${source.name} — ${source.path}` }))}
        />
      </div>

      <div className="logs-workspace">
        <aside className="logs-rail" aria-label="Log sources">
          <div className="logs-rail-head">
            <span className="logs-rail-title">Log sources</span>
            <span className="logs-rail-count">
              {scan.status === "ready" ? `${scan.sources.length}${scan.partial ? "+" : ""}` : "—"}
            </span>
          </div>
          <div className="logs-rail-search">
            <Search aria-hidden />
            <input
              type="text"
              placeholder="Filter sources…"
              value={sourceQuery}
              onChange={(e) => setSourceQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown" || e.key === "Enter") {
                  e.preventDefault();
                  const first = document.querySelector<HTMLButtonElement>(".logs-groups .logs-source");
                  first?.focus();
                }
              }}
              aria-label="Filter log sources"
            />
          </div>
          <div className="logs-groups" role="listbox" aria-label="Log sources">
            {scan.status === "scanning" && (
              <div className="logs-skeleton" aria-hidden>
                {[0, 1, 2].map((i) => <span key={i} />)}
              </div>
            )}
            {scan.status === "idle" && (
              <div className="logs-rail-empty">
                <strong>No scan yet</strong>
                <span>Run a scan to find log sources on this server.</span>
              </div>
            )}
            {scan.status === "error" && (
              <div className="logs-rail-empty">
                <strong>Scan failed</strong>
                <span>{scan.error}</span>
              </div>
            )}
            {scan.status === "ready" && scan.sources.length === 0 && (
              <div className="logs-rail-empty">
                <strong>No log sources found</strong>
                <span>Nothing readable was found under /var/log or your added paths.</span>
              </div>
            )}
            {grouped.map(({ group, label, items }) => (
              <div key={group} className="logs-group">
                <div className="logs-group-title">
                  <span>{label}</span>
                  <span className="logs-group-count">{items.length}</span>
                </div>
                {items.map((s) => {
                  const sourceIndex = allVisibleSources.findIndex((it) => it.path === s.path);
                  const isFocused = sourceIndex === focusedSourceIndex || (focusedSourceIndex === -1 && selected === s.path);
                  return (
                    <button
                      key={s.path}
                      type="button"
                      role="option"
                      tabIndex={isFocused ? 0 : -1}
                      aria-selected={selected === s.path}
                      className={`logs-source ${selected === s.path ? "is-active" : ""} ${!s.readable ? "is-unreadable" : ""}`}
                      onFocus={() => setFocusedSourceIndex(sourceIndex)}
                      onClick={() => selectSource(s.path)}
                      onKeyDown={(e) => handleSourceRowKeyDown(e, s.path, sourceIndex)}
                      title={s.path}
                    >
                      <span className="logs-source-name">
                        <span>{s.name}</span>
                        {!s.readable && <Lock size={10} aria-label="Not readable" />}
                      </span>
                      <span className="logs-source-meta">
                        {sizeLabel(s.size)} · {ageLabel(s.age_sec)} ago
                      </span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="logs-rail-add">
            <input
              type="text"
              placeholder="/var/log/custom.log"
              value={manualPath}
              onChange={(e) => setManualPath(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void addSource(); }}
              aria-label="Add a log path"
            />
            <Button variant="outline" size="sm" onClick={() => void addSource()} disabled={adding || !manualPath.trim()}>
              {adding ? "Adding…" : "Add"}
            </Button>
          </div>
          {addError && <div className="logs-add-error" role="alert">{addError}</div>}
        </aside>

        <div className="logs-viewer">
          <div className="logs-viewer-toolbar">
            <span className="logs-path" title={selected ?? undefined}>
              {selected ?? "Select a log source"}
            </span>
            {followActive && (
              <span className={`logs-live-badge ${follow.status === "eof" ? "is-ended" : ""}`}>
                <span className="logs-live-dot" aria-hidden />
                {follow.status === "starting" ? "Starting" : follow.status === "eof" ? "Ended" : "Live"}
              </span>
            )}
            <Button
              variant={followRunning ? "default" : "outline"}
              size="sm"
              onClick={toggleFollow}
              disabled={!selected || (!followRunning && (read.status !== "ready" || !selectedSource?.readable))}
              title={!selected
                ? "Select a source first"
                : followRunning
                  ? "Stop following"
                  : binarySelected
                    ? "Binary files can be downloaded but not followed"
                    : read.status === "loading"
                      ? "Wait for the text check to finish"
                      : !selectedSource?.readable
                        ? "This source is not readable"
                        : "Tail the log live"}
            >
              {followRunning ? <><Pause /> Stop</> : <><Play /> Follow</>}
            </Button>
            <OarsSelect
              className="logs-linecount"
              value={String(lineCount)}
              onValueChange={(value) => changeLineCount(Number(value) as LineCount)}
              disabled={followRunning}
              aria-label="Lines to load"
              title={followRunning ? "Stop following to change the loaded history" : undefined}
              options={[
                { value: "200", label: "200 lines" },
                { value: "500", label: "500 lines" },
                { value: "1000", label: "1,000 lines" },
                { value: "5000", label: "5,000 lines" },
              ]}
            />
            <div className="logs-search">
              <Search aria-hidden />
              <input
                type="text"
                placeholder="Search loaded lines…"
                value={viewerQuery}
                onChange={(e) => setViewerQuery(e.target.value)}
                aria-label="Search loaded lines"
                disabled={binarySelected || read.status === "unreadable"}
              />
            </div>
            {viewerQuery.trim() !== "" && (
              <span className="logs-matches">
                {viewerMatches === 0 ? "No matches" : `${viewerMatches} match${viewerMatches === 1 ? "" : "es"}`}
              </span>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => void startDownload()}
              disabled={!selected || download.status === "starting" || download.status === "running"}
              title={!selected ? "Select a source first" : undefined}
            >
              <Download />
              {download.status === "starting" || download.status === "running" ? "Downloading…" : "Download"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="oars-danger-ghost"
              onClick={() => selectedSource && openClear(selectedSource)}
              disabled={!selectedSource}
              title={!selectedSource ? "Select a source first" : "Truncate this log on the server"}
            >
              <Trash2 /> Clear
            </Button>
          </div>

          {followActive && follow.dropped > 0 && (
            <div className="logs-banner logs-banner-warn" role="status">
              <AlertTriangle />
              <div>
                <strong>Some lines were dropped</strong>
                <span>The follow stream overflowed its buffer; about {sizeLabel(follow.dropped)} was skipped.</span>
              </div>
            </div>
          )}
          {followActive && follow.status === "eof" && (
            <div className="logs-banner logs-banner-warn" role="status">
              <AlertTriangle />
              <div>
                <strong>The source stopped or disappeared</strong>
                <span>Follow ended because the log file is no longer being written. The last content is still shown.</span>
              </div>
            </div>
          )}
          {follow.status === "error" && (
            <div className="logs-banner logs-banner-error" role="alert">
              <AlertTriangle />
              <div><strong>Follow failed</strong><span>{follow.error}</span></div>
            </div>
          )}
          {!followActive && read.sourcePath === selected && read.status === "ready" && read.limited && (
            <div className="logs-banner logs-banner-warn" role="status">
              <AlertTriangle />
              <div>
                <strong>Read hit the size safety limit</strong>
                <span>The loaded lines may be incomplete. Download the file for the full content.</span>
              </div>
            </div>
          )}

          <div ref={bodyRef} className="logs-body" onScroll={handleBodyScroll} role="log" aria-live="polite" aria-atomic="false" tabIndex={0} aria-label="Log lines">
            {!followActive && read.status === "loading" && read.lines.length === 0 && (
              <div className="logs-skeleton logs-skeleton-rows" aria-hidden>
                {[0, 1, 2, 3].map((i) => <span key={i} />)}
              </div>
            )}
            {!followActive && read.status === "loading" && read.lines.length > 0 && (
              <div className="logs-loading-chip">Refreshing…</div>
            )}
            {!followActive && read.status === "unreadable" && selectedSource && (
              <div className="logs-empty">
                <strong>This source is not readable</strong>
                <span>
                  The connected account cannot read {selectedSource.path}. Connect as root or check the
                  file's permissions on {server.name}.
                </span>
              </div>
            )}
            {!followActive && binarySelected && (
              <div className="logs-empty logs-binary">
                <FileWarning aria-hidden />
                <strong>This file is not text</strong>
                <span>Oars found binary or invalid text data and did not render it. Download the file to inspect it safely.</span>
                <Button variant="outline" size="sm" onClick={() => void startDownload()}>
                  <Download /> Download file
                </Button>
              </div>
            )}
            {!followActive && read.status === "error" && (
              <div className="logs-empty">
                <strong>This log could not be read</strong>
                <span>{read.error}</span>
                <Button variant="outline" size="sm" onClick={() => setReloadTick((t) => t + 1)}>
                  Try again
                </Button>
              </div>
            )}
            {followRunning && followData.length === 0 && (
              <div className="logs-empty">
                <strong>Waiting for new lines…</strong>
                <span>The follow stream is open and will append as the file is written.</span>
              </div>
            )}
            {!followActive && read.status === "idle" && !selected && (
              <div className="logs-empty">
                <strong>Select a log source</strong>
                <span>Choose a source from the rail to read its recent lines.</span>
              </div>
            )}
            {!followActive && read.status === "ready" && read.lines.length === 0 && (
              <div className="logs-empty">
                <strong>No lines to show</strong>
                <span>The file is empty or returned no lines.</span>
              </div>
            )}
            {displayLines.length > 0 && (
              <div className="logs-virtual-list" style={{ height: `${lineVirtualizer.getTotalSize()}px` }}>
                {lineVirtualizer.getVirtualItems().map((virtualRow) => (
                  <div
                    key={virtualRow.key}
                    ref={lineVirtualizer.measureElement}
                    data-index={virtualRow.index}
                    className="logs-line"
                    style={{ transform: `translateY(${virtualRow.start}px)` }}
                  >
                    {renderLineContent(displayLines[virtualRow.index])}
                  </div>
                ))}
              </div>
            )}
            {displayLines.length > 0 && viewerMatches === 0 && viewerQuery.trim() !== "" && (
              <div className="logs-no-matches">No matches for “{viewerQuery.trim()}” in the loaded lines</div>
            )}
            {followActive && stickToLatest && (
              <button type="button" className="logs-jump" onClick={jumpToLatest}>
                Jump to latest <ChevronDown />
              </button>
            )}
          </div>

          {download.status !== "idle" && (
            <div className="logs-download" role="status">
              {download.status === "starting" && <RefreshCw className="spin" aria-hidden />}
              {download.status === "running" && <Download aria-hidden />}
              {download.status === "done" && <Check className="logs-download-ok" aria-hidden />}
              {download.status === "failed" && <AlertTriangle className="logs-download-bad" aria-hidden />}
              {download.status === "canceled" && <X className="logs-download-bad" aria-hidden />}
              <div className="logs-download-copy">
                <strong>
                  {download.status === "starting" && "Starting download…"}
                  {download.status === "running" && `Downloading — ${sizeLabel(download.bytes)} of ${sizeLabel(download.total)}`}
                  {download.status === "done" && `Saved ${sizeLabel(download.bytes)} to ${download.localPath}`}
                  {download.status === "failed" && `Download failed — ${download.error}`}
                  {download.status === "canceled" && "Download canceled."}
                </strong>
                {download.status === "running" && download.total > 0 && (
                  <span
                    className="logs-progress"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={downloadPercent}
                    aria-label="Log download progress"
                    aria-valuetext={`${downloadPercent}% (${sizeLabel(download.bytes)} of ${sizeLabel(download.total)})`}
                  >
                    <span style={{ width: `${downloadPercent}%` }} />
                  </span>
                )}
              </div>
              {download.status === "running" && (
                <Button variant="outline" size="sm" onClick={() => void cancelDownload()}>
                  Cancel
                </Button>
              )}
              {(download.status === "done" || download.status === "failed" || download.status === "canceled") && (
                <Button variant="ghost" size="sm" onClick={dismissDownload} aria-label="Dismiss download status">
                  <X />
                </Button>
              )}
            </div>
          )}

          <footer className="logs-viewer-footer">
            <span className="logs-footer-count">
              {displayLines.length} line{displayLines.length === 1 ? "" : "s"}
              {followActive ? " · follow stream" : ""}
            </span>
            {followTrimmed && (
              <span className="logs-footer-note">Showing the most recent 1 MB of the follow stream.</span>
            )}
          </footer>
        </div>
      </div>

      {clearTarget && (
        <LogClearModal
          clearTarget={clearTarget}
          server={server}
          clearBusy={clearBusy}
          clearError={clearError}
          clearIsConflict={clearIsConflict}
          clearResult={clearResult}
          scan={scan}
          closeClear={closeClear}
          confirmClear={confirmClear}
          rescanForClear={rescanForClear}
        />
      )}
    </section>
  );
}

function LogClearModal({
  clearTarget,
  server,
  clearBusy,
  clearError,
  clearIsConflict,
  clearResult,
  scan,
  closeClear,
  confirmClear,
  rescanForClear,
}: {
  clearTarget: LogSource;
  server: Server;
  clearBusy: boolean;
  clearError: string | null;
  clearIsConflict: boolean;
  clearResult: { before: number; after: number } | null;
  scan: any;
  closeClear: () => void;
  confirmClear: () => Promise<void>;
  rescanForClear: () => Promise<void>;
}) {
  const dialogRef = useModalFocus(closeClear, "[data-logs-clear-confirm]", !clearBusy);
  return (
    <ApplicationOverlay
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !clearBusy) closeClear();
      }}
    >
      <div
        ref={dialogRef}
        className="oars-modal oars-modal-narrow logs-clear-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="logs-clear-title"
        aria-describedby="logs-clear-description"
      >
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon oars-modal-icon-danger">
              <AlertTriangle />
            </span>
            <div>
              <h2 id="logs-clear-title">Clear this log on the server?</h2>
              <p id="logs-clear-description" className="oars-modal-subtitle">
                This truncates the file on {server.name}. Permanent. Download first if needed.
              </p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Close"
              onClick={closeClear}
              disabled={clearBusy}
            >
              <X />
            </Button>
          </div>
        </header>
        <div className="oars-modal-body">
          <div className="monitor-affected-resource">
            <strong>{server.name}</strong>
            <span>{clearTarget.path}</span>
          </div>
          <dl className="logs-clear-facts">
            <div>
              <dt>Current size</dt>
              <dd>{sizeLabel(clearTarget.size)}</dd>
            </div>
            <div>
              <dt>Last modified</dt>
              <dd>{formatMtime(clearTarget.mtime_epoch)}</dd>
            </div>
            <div>
              <dt>Permissions</dt>
              <dd>{modeLabel(clearTarget.mode)}</dd>
            </div>
          </dl>
          <p className="monitor-approval-warning">
            The file is truncated to zero bytes on the server. This cannot be undone. Download the log
            first if you may need it.
          </p>
          {clearError && (
            <div className="logs-clear-error" role="alert">
              <strong>Clear refused</strong>
              <span>{clearError}</span>
              {clearIsConflict && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void rescanForClear()}
                  disabled={scan.status === "scanning"}
                >
                  <RefreshCw className={scan.status === "scanning" ? "spin" : ""} />
                  Re-scan and review
                </Button>
              )}
            </div>
          )}
          {clearResult && (
            <div className="logs-clear-result" role="status">
              <Check />
              <span>
                Cleared — {sizeLabel(clearResult.before)} → {sizeLabel(clearResult.after)}. The change is
                recorded in the audit log.
              </span>
            </div>
          )}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={closeClear} disabled={clearBusy}>
              {clearResult ? "Done" : "Cancel"}
            </Button>
            {!clearResult && (
              <Button
                data-logs-clear-confirm
                variant="destructive"
                onClick={() => void confirmClear()}
                disabled={clearBusy}
              >
                {clearBusy ? "Clearing…" : "Clear log"}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}
