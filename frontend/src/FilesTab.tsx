import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  ArrowUp,
  Copy,
  Download,
  Eye,
  EyeOff,
  File,
  FileArchive,
  FileQuestion,
  FileText,
  Folder,
  FolderInput,
  FolderOpen,
  FolderPlus,
  HardDrive,
  Laptop,
  Link2,
  Loader2,
  Pencil,
  RefreshCw,
  Trash2,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import { api, BridgeError, pickDirectory, pickSaveFile } from "./bridge";
import { OarsLoadingState } from "./components/OarsLoadingState";
import { Button } from "./components/ui/button";
import type { LocalEntry, RemotePath, SftpEntry, SftpTransfer, SftpTransferStatus } from "./types";
import {
  base64ToBytes,
  bytesToBase64,
  entryHidden,
  entryKey,
  rpDisplay,
  rpFromUtf8,
  rpJoin,
  rpParent,
  rpSerialize,
  rpStem,
  ROOT,
  validateLeafName,
} from "./sftp-path";
import {
  DirCache,
  emptySelection,
  emptySnapshot,
  isCurrentDirRequest,
  permissionStringToOctal,
  selectionAll,
  selectionHas,
  selectionRange,
  selectionSelectOnly,
  selectionToggle,
  type DirSnapshot,
  type SelectionModel,
} from "./file-state";
import {
  EDITOR_MAX_BYTES,
  editorSaveParams,
  isConflictError,
  savedIdentityFallback,
  sha256Hex,
} from "./editor-state";
import {
  MAX_CONCURRENT_UPLOADS,
  UPLOAD_CHUNK_BYTES,
  directoryUploadSupported,
  emptyUploadModel,
  fileRelativePath,
  nextUploadOffset,
  uploadActive,
  uploadDirectoryPaths,
  uploadJobFor,
  uploadReducer,
  type UploadJob,
} from "./transfer-model";
import { localJoin, localParent } from "./local-path";

// --- formatting helpers ------------------------------------------------------

function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtTime(epoch: number): string {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

function errMessage(e: unknown): string {
  return e instanceof BridgeError ? e.message : e instanceof Error ? e.message : String(e);
}

/** Safe display for a backend transfer path (raw bytes can be invalid
 * UTF-8; the backend records the raw path). */
function transferDisplay(path: string): string {
  try {
    return decodeURIComponent(escape(path));
  } catch {
    return "\uFFFD".repeat(path.length) || path;
  }
}

function kindLabel(kind: SftpEntry["kind"]): string {
  return kind === "file" ? "File" : kind === "dir" ? "Folder" : kind === "symlink" ? "Symlink" : "Other";
}

function isZipEntry(entry: SftpEntry): boolean {
  return entry.kind === "file" && entry.display.toLowerCase().endsWith(".zip");
}

// --- file icon ---------------------------------------------------------------

function FileIcon({ entry, size = 16 }: { entry: SftpEntry; size?: number }) {
  if (entry.kind === "dir") return <Folder size={size} className="fs-kind-dir" aria-hidden />;
  if (entry.kind === "symlink") return <Link2 size={size} className="fs-kind-link" aria-hidden />;
  if (entry.kind === "other") return <FileQuestion size={size} className="fs-kind-other" aria-hidden />;
  const lower = entry.display.toLowerCase();
  if (lower.endsWith(".zip") || lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return <FileArchive size={size} className="fs-kind-archive" aria-hidden />;
  }
  return <FileText size={size} className="fs-kind-file" aria-hidden />;
}

// --- approval dialog shell ---------------------------------------------------

interface ApprovalDialogProps {
  icon: React.ReactNode;
  iconClass: string;
  title: string;
  subtitle: React.ReactNode;
  children?: React.ReactNode;
  actions: React.ReactNode;
  onCancel: () => void;
  busy?: boolean;
  labelledBy: string;
}

function ApprovalDialog({ icon, iconClass, title, subtitle, children, actions, onCancel, busy = false, labelledBy }: ApprovalDialogProps) {
  return (
    <div className="oars-modal-overlay" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onCancel(); }}>
      <div className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby={labelledBy}>
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className={`oars-modal-icon ${iconClass}`}>{icon}</span>
            <div>
              <h2 id={labelledBy}>{title}</h2>
              <p className="oars-modal-subtitle">{subtitle}</p>
            </div>
            <Button variant="ghost" size="icon-sm" className="oars-modal-close" onClick={onCancel} disabled={busy} aria-label="Close dialog"><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body">{children}</div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-left" />
          <div className="oars-modal-actions-right">{actions}</div>
        </footer>
      </div>
    </div>
  );
}

function MonoPath({ rp }: { rp: RemotePath }) {
  return <code className="fs-mono-path">{rpDisplay(rp)}</code>;
}

/** Shared lifecycle for approval dialogs. The action owns validation; this
 * hook owns the one-shot busy state and consistent bridge-error display. */
function useDialogAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async (action: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(errMessage(cause));
      setBusy(false);
    }
  }, [busy]);
  return { busy, error, run };
}

// --- editor modal ------------------------------------------------------------

interface EditorState {
  path: RemotePath;
  pathKey: string;
  display: string;
  /** The entry as opened: size/mtime are the conflict-check identity. */
  entry: SftpEntry;
  content: string;
  sha256: string;
  dirty: boolean;
  phase: "loading" | "editing" | "saving" | "error";
  error: string | null;
  /** Non-null when the last save was refused with a conflict. */
  conflict: string | null;
  tooLarge: boolean;
}

interface FilesTabProps {
  serverId: string;
  /** Add Application navigates to the current server's Deploy tab. */
  onNavigateToDeploy?: () => void;
}

interface UploadIntent {
  file: File;
  relativePath?: string;
}

interface LocalPaneState {
  path: string | null;
  entries: LocalEntry[];
  loading: boolean;
  error: string | null;
  truncated: boolean;
  selected: string[];
}

type DialogState =
  | { kind: "mkdir" }
  | { kind: "rename"; entry: SftpEntry }
  | { kind: "chmod"; entry: SftpEntry }
  | { kind: "delete"; entries: SftpEntry[] }
  | { kind: "unzip"; entry: SftpEntry }
  | { kind: "upload"; intents: UploadIntent[] }
  | { kind: "uploadLocal"; entries: LocalEntry[] }
  | null;

// --- main component ----------------------------------------------------------

export function FilesTab({ serverId, onNavigateToDeploy }: FilesTabProps) {
  const [dir, setDir] = useState<DirSnapshot>(() => emptySnapshot(serverId, ROOT));
  const [selection, setSelection] = useState<SelectionModel>(emptySelection);
  const [showHidden, setShowHidden] = useState(false);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [transfers, setTransfers] = useState<SftpTransfer[]>([]);
  const [sizes, setSizes] = useState<Map<string, { size: number | null; loading: boolean; error: string | null }>>(new Map());
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [local, setLocal] = useState<LocalPaneState>({ path: null, entries: [], loading: false, error: null, truncated: false, selected: [] });

  const generationRef = useRef(0);
  const cacheRef = useRef(new DirCache());
  const cancelledRef = useRef(new Set<number>());
  const observedFinalRef = useRef(new Set<number>());
  const localObservedFinalRef = useRef(new Set<number>());
  const editorRequestRef = useRef(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);
  const [pollingTransfers, setPollingTransfers] = useState(false);
  const [uploads, dispatchUpload] = useReducer(uploadReducer, undefined, emptyUploadModel);

  const refreshAfterMutation = useCallback((path: RemotePath) => {
    setSizes(new Map());
    loadDir(serverId, path);
  }, [serverId]);

  // --- directory loading (source-bound) ---------------------------------------

  const loadDir = useCallback(async (server: string, path: RemotePath, background = false) => {
    const pathKey = rpSerialize(path);
    const generation = ++generationRef.current;
    const token = { generation, serverId: server, pathKey };
    const now = Date.now();
    const cached = cacheRef.current.get(server, pathKey, now);
    if (cached) {
      setDir((prev) => ({
        ...prev,
        serverId: server,
        path,
        pathKey,
        listing: cached,
        loading: false,
        refreshing: !background,
        error: null,
        loadedAt: now,
      }));
      if (background) return; // pure cache hit — no network
    } else {
      setDir((prev) => ({
        ...prev,
        serverId: server,
        path,
        pathKey,
        // Keep the prior list during refresh (spec 05 §4.3) — only when
        // the previous snapshot was for this same directory.
        listing: prev.serverId === server && prev.pathKey === pathKey ? prev.listing : { entries: [], truncated: false },
        loading: true,
        refreshing: false,
        error: null,
      }));
    }
    try {
      const r = await api.sftp.ls(server, path);
      if (!isCurrentDirRequest(token, generationRef.current, server, pathKey)) return;
      cacheRef.current.set(server, pathKey, { entries: r.entries, truncated: r.truncated }, Date.now());
      setDir({
        serverId: server,
        path,
        pathKey,
        listing: { entries: r.entries, truncated: r.truncated },
        loading: false,
        refreshing: false,
        error: null,
        loadedAt: Date.now(),
      });
    } catch (e) {
      if (!isCurrentDirRequest(token, generationRef.current, server, pathKey)) return;
      setDir((prev) => ({ ...prev, loading: false, refreshing: false, error: errMessage(e) }));
    }
  }, []);

  // First load + server change: reset everything for the new identity.
  useEffect(() => {
    generationRef.current += 1;
    setDir(emptySnapshot(serverId, ROOT));
    setSelection(emptySelection());
    setTransfers([]);
    setSizes(new Map());
    setEditor(null);
    editorRequestRef.current += 1;
    setDialog(null);
    cancelledRef.current.clear();
    observedFinalRef.current.clear();
    localObservedFinalRef.current.clear();
    setPollingTransfers(false);
    loadDir(serverId, ROOT);
  }, [serverId, loadDir]);

  // --- selection helpers -------------------------------------------------------

  const displayedEntries = useMemo(() => {
    return dir.listing.entries.filter((e) => showHidden || !entryHidden(e));
  }, [dir.listing.entries, showHidden]);

  const displayedKeys = useMemo(() => displayedEntries.map(entryKey), [displayedEntries]);

  const selectedEntries = useMemo(() => {
    return displayedEntries.filter((e) => selectionHas(selection, entryKey(e)));
  }, [displayedEntries, selection]);

  const onRowClick = useCallback((e: React.MouseEvent, entry: SftpEntry) => {
    const key = entryKey(entry);
    if (e.shiftKey) {
      setSelection((sel) => selectionRange(sel, displayedKeysRef.current, key));
    } else if (e.metaKey || e.ctrlKey) {
      setSelection((sel) => selectionToggle(sel, key));
    } else {
      setSelection(selectionSelectOnly(selectionRef.current, key));
    }
  }, []);
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const displayedKeysRef = useRef(displayedKeys);
  displayedKeysRef.current = displayedKeys;

  // --- keyboard behavior (spec 05 §4.1) ---------------------------------------

  const openEntry = useCallback(async (entry: SftpEntry, parent: RemotePath) => {
    const path = rpJoin(parent, entry.name);
    if (entry.kind === "dir") {
      setSelection(emptySelection());
      loadDir(serverId, path);
      return;
    }
    if (entry.kind === "file") {
      openEditor(entry, path);
      return;
    }
    if (entry.kind === "symlink") {
      // Symlinks can point at either: try a directory listing first, then
      // fall back to the text editor (SFTP follows the link server-side).
      try {
        const r = await api.sftp.ls(serverId, path);
        setSelection(emptySelection());
        cacheRef.current.set(serverId, rpSerialize(path), { entries: r.entries, truncated: r.truncated }, Date.now());
        loadDir(serverId, path);
      } catch {
        openEditor(entry, path);
      }
      return;
    }
    setDir((prev) => ({ ...prev, error: `This entry type (${kindLabel(entry.kind)}) cannot be opened.` }));
  }, [serverId, loadDir]);

  /** Enter opens the focused row, Delete confirms its removal — rows are
   * focusable so keyboard-first navigation works without a mouse. */
  const onRowKeyDown = useCallback((e: React.KeyboardEvent, entry: SftpEntry) => {
    if (e.key === "Enter") {
      e.preventDefault();
      e.stopPropagation();
      void openEntry(entry, dirRef.current.path);
    } else if (e.key === "Delete" || e.key === "Backspace") {
      e.preventDefault();
      e.stopPropagation();
      setDialog({ kind: "delete", entries: [entry] });
    }
  }, [openEntry]);

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    const target = e.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
    if (e.key === "Escape") {
      if (dialog) { setDialog(null); return; }
      if (selection.keys.length > 0) { setSelection(emptySelection()); return; }
      return;
    }
    if (e.key === "a" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      setSelection(selectionAll(displayedKeysRef.current));
      return;
    }
    if (e.key === "Enter") {
      const first = selectedEntriesRef.current[0];
      if (first) openEntry(first, dirRef.current.path);
      return;
    }
    if (e.key === "Delete" || e.key === "Backspace") {
      const sel = selectedEntriesRef.current;
      if (sel.length > 0) {
        e.preventDefault();
        setDialog({ kind: "delete", entries: sel });
      }
    }
  }, [dialog, selection.keys]);
  const selectedEntriesRef = useRef(selectedEntries);
  selectedEntriesRef.current = selectedEntries;
  const dirRef = useRef(dir);
  dirRef.current = dir;

  // --- transfer polling (only while active or recent) --------------------------

  const anyUploadActive = useMemo(() => uploads.jobs.some(uploadActive), [uploads.jobs]);
  const anyTransferActive = useMemo(
    () => transfers.some((t) => t.status === "queued" || t.status === "running"),
    [transfers],
  );

  useEffect(() => {
    if (!pollingTransfers && !anyTransferActive && !anyUploadActive) return;
    let stopped = false;
    let timer: number | undefined;
    let quietPolls = 0;
    const poll = async () => {
      try {
        const snap = await api.sftp.poll(serverId);
        if (stopped) return;
        setTransfers(snap.transfers);
        const active = snap.transfers.some((t) => t.status === "queued" || t.status === "running");
        const newlyFinished = snap.transfers.filter((t) =>
          (t.status === "done" || t.status === "failed" || t.status === "canceled")
          && !observedFinalRef.current.has(t.id));
        if (newlyFinished.length > 0) {
          for (const transfer of newlyFinished) observedFinalRef.current.add(transfer.id);
          refreshAfterMutation(dirRef.current.path);
        }
        quietPolls = active ? 0 : quietPolls + 1;
        if (!active && !anyUploadActive && quietPolls >= 2) setPollingTransfers(false);
      } catch {
        // A failed poll keeps the last snapshot; the drawer never lies
        // about a transfer it cannot observe.
      }
    };
    poll();
    timer = window.setInterval(poll, 800);
    return () => { stopped = true; if (timer !== undefined) window.clearInterval(timer); };
  }, [serverId, anyTransferActive, anyUploadActive, pollingTransfers, refreshAfterMutation]);

  // --- uploads -----------------------------------------------------------------

  const runUpload = useCallback(async (job: UploadJob) => {
    const { transferId, serverId: server, path, file, total } = job;
    dispatchUpload({ type: "start", transferId });
    let offset = 0;
    try {
      if (total === 0) {
        const empty = await api.sftp.write(server, path, 0, "", transferId, 0);
        if (!empty.done || empty.written !== 0) throw new Error("The server did not finalize the empty file.");
      }
      while (offset < total) {
        if (cancelledRef.current.has(transferId)) {
          await api.sftp.cancel(server, transferId).catch(() => {});
          dispatchUpload({ type: "canceled", transferId });
          return;
        }
        const chunk = file.slice(offset, Math.min(offset + UPLOAD_CHUNK_BYTES, total));
        const buf = new Uint8Array(await chunk.arrayBuffer());
        const r = await api.sftp.write(server, path, offset, bytesToBase64(buf), transferId, total);
        offset = nextUploadOffset(offset, buf.length, r.written, total);
        dispatchUpload({ type: "progress", transferId, bytesSent: offset });
      }
      dispatchUpload({ type: "done", transferId });
      refreshAfterMutation(dirRef.current.path);
    } catch (e) {
      await api.sftp.cancel(server, transferId).catch(() => {});
      dispatchUpload({ type: "failed", transferId, error: errMessage(e) });
    }
  }, [refreshAfterMutation]);

  const ensureRemoteDirectory = useCallback(async (path: RemotePath) => {
    try {
      const existing = await api.sftp.stat(serverId, path);
      if (existing.entry.kind !== "dir") throw new Error(`${rpDisplay(path)} already exists and is not a folder.`);
      return;
    } catch (statError) {
      try {
        await api.sftp.mkdir(serverId, path);
      } catch (mkdirError) {
        try {
          const raced = await api.sftp.stat(serverId, path);
          if (raced.entry.kind === "dir") return;
        } catch { /* surface the mkdir failure below */ }
        throw mkdirError instanceof Error ? mkdirError : statError;
      }
    }
  }, [serverId]);

  const startUploads = useCallback(async (intents: UploadIntent[], parent: RemotePath) => {
    const directories = uploadDirectoryPaths(parent, intents.map((intent) => intent.relativePath));
    for (const directory of directories) await ensureRemoteDirectory(directory);
    const jobs = intents.map((i) => uploadJobFor(serverId, parent, i.file, i.relativePath));
    for (const job of jobs) dispatchUpload({ type: "register", job });
    let index = 0;
    const workers = Array.from({ length: Math.min(MAX_CONCURRENT_UPLOADS, jobs.length) }, async () => {
      while (index < jobs.length) {
        const job = jobs[index++];
        await runUpload(job);
      }
    });
    void Promise.all(workers);
  }, [serverId, runUpload, ensureRemoteDirectory]);

  const cancelUpload = useCallback(async (job: UploadJob) => {
    cancelledRef.current.add(job.transferId);
    if (job.status === "running") {
      await api.sftp.cancel(serverId, job.transferId).catch(() => {});
      dispatchUpload({ type: "canceled", transferId: job.transferId });
    } else if (job.status === "queued") {
      dispatchUpload({ type: "canceled", transferId: job.transferId });
    }
  }, [serverId]);

  const handleFiles = useCallback((files: FileList | File[], parent: RemotePath, relativeBase?: string) => {
    const intents: UploadIntent[] = Array.from(files).map((f) => ({
      file: f,
      relativePath: relativeBase !== undefined ? `${relativeBase}/${f.name}` : fileRelativePath(f),
    }));
    if (intents.length === 0) return;
    setDialog({ kind: "upload", intents });
  }, []);

  // --- downloads ---------------------------------------------------------------

  const watchTransfer = useCallback((opId: number) => {
    observedFinalRef.current.delete(opId);
    setPollingTransfers(true);
  }, []);

  const loadLocal = useCallback(async (path: string) => {
    setLocal((current) => ({ ...current, path, loading: true, error: null, selected: [] }));
    try {
      const result = await api.local.ls(path);
      setLocal((current) => current.path === path ? {
        path,
        entries: result.entries,
        loading: false,
        error: null,
        truncated: result.truncated,
        selected: [],
      } : current);
    } catch (cause) {
      setLocal((current) => current.path === path ? { ...current, loading: false, error: errMessage(cause), selected: [] } : current);
    }
  }, []);

  const chooseLocalFolder = useCallback(async () => {
    const path = await pickDirectory("Choose a local folder", local.path ?? undefined);
    if (path) await loadLocal(path);
  }, [local.path, loadLocal]);

  useEffect(() => {
    if (!local.path) return;
    const completedDownloads = transfers.filter((transfer) =>
      (transfer.kind === "download" || transfer.kind === "zip_download")
      && transfer.status === "done"
      && !localObservedFinalRef.current.has(transfer.id));
    if (completedDownloads.length === 0) return;
    for (const transfer of completedDownloads) localObservedFinalRef.current.add(transfer.id);
    void loadLocal(local.path);
  }, [transfers, local.path, loadLocal]);

  const selectedLocalEntries = useMemo(
    () => local.entries.filter((entry) => local.selected.includes(entry.path)),
    [local.entries, local.selected],
  );

  const toggleLocalEntry = useCallback((entry: LocalEntry, additive: boolean) => {
    setLocal((current) => ({
      ...current,
      selected: additive
        ? current.selected.includes(entry.path)
          ? current.selected.filter((path) => path !== entry.path)
          : [...current.selected, entry.path]
        : [entry.path],
    }));
  }, []);

  const startLocalUploads = useCallback(async (entries: LocalEntry[]) => {
    const files = entries.filter((entry) => entry.kind === "file");
    for (const entry of files) {
      const started = await api.sftp.uploadLocal(serverId, entry.path, rpJoin(dirRef.current.path, rpFromUtf8(entry.name)));
      watchTransfer(started.op_id);
    }
    setLocal((current) => ({ ...current, selected: [] }));
  }, [serverId, watchTransfer]);

  const downloadPaths = useCallback(async (entries: SftpEntry[]) => {
    if (entries.length === 0) return;
    const parent = dirRef.current.path;
    if (entries.length === 1 && entries[0].kind === "file") {
      const path = rpJoin(parent, entries[0].name);
      const destination = local.path
        ? localJoin(local.path, rpDisplay(entries[0].name))
        : await pickSaveFile(`Save ${rpDisplay(entries[0].name)}`, rpDisplay(entries[0].name));
      if (destination === null) return; // dialog cancellation starts nothing
      const started = await api.sftp.download(serverId, path, destination);
      watchTransfer(started.op_id);
      return;
    }
    const defaultName = entries.length === 1 ? `${rpDisplay(entries[0].name)}.zip` : "oars-download.zip";
    const destination = local.path
      ? localJoin(local.path, defaultName)
      : await pickSaveFile("Save selection as a ZIP archive", defaultName);
    if (destination === null) return;
    const started = await api.sftp.zipDownload(serverId, entries.map((e) => rpJoin(parent, e.name)), destination);
    watchTransfer(started.op_id);
  }, [serverId, watchTransfer, local.path]);

  const copyPath = useCallback(async (entry: SftpEntry) => {
    const path = rpJoin(dirRef.current.path, entry.name);
    await navigator.clipboard.writeText(rpDisplay(path));
  }, []);

  // --- editor ------------------------------------------------------------------

  const openEditor = useCallback(async (entry: SftpEntry, path: RemotePath) => {
    const pathKey = rpSerialize(path);
    const display = rpDisplay(path);
    const requestId = ++editorRequestRef.current;
    const updateCurrentEditor = (update: (current: EditorState) => EditorState) => {
      setEditor((current) => {
        if (!current || current.pathKey !== pathKey || editorRequestRef.current !== requestId) return current;
        return update(current);
      });
    };
    if (entry.size > EDITOR_MAX_BYTES) {
      setEditor({
        path, pathKey, display, entry,
        content: "", sha256: "",
        dirty: false, phase: "error",
        error: `This file is ${fmtBytes(entry.size)} — the editor handles text files up to ${fmtBytes(EDITOR_MAX_BYTES)}.`,
        conflict: null, tooLarge: true,
      });
      return;
    }
    setEditor({ path, pathKey, display, entry, content: "", sha256: "", dirty: false, phase: "loading", error: null, conflict: null, tooLarge: false });
    try {
      const chunks: Uint8Array[] = [];
      let offset = 0;
      while (true) {
        const remaining = EDITOR_MAX_BYTES - offset;
        const max = Math.min(64 * 1024, Math.max(1, remaining + 1));
        const r = await api.sftp.read(serverId, path, offset, max);
        if (editorRequestRef.current !== requestId) return;
        const chunk = base64ToBytes(r.base64);
        if (offset + chunk.length > EDITOR_MAX_BYTES) {
          updateCurrentEditor((current) => ({
            ...current,
            phase: "error",
            tooLarge: true,
            error: `This file grew beyond ${fmtBytes(EDITOR_MAX_BYTES)} while it was opening. Reload after the remote write finishes.`,
          }));
          return;
        }
        chunks.push(chunk);
        offset += chunk.length;
        if (r.eof) break;
        if (chunk.length === 0) throw new Error("The server returned an incomplete file read.");
      }
      const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
      let at = 0;
      for (const c of chunks) { bytes.set(c, at); at += c.length; }
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        updateCurrentEditor((current) => ({ ...current, phase: "error", error: "This file is not valid UTF-8 text and cannot be edited safely." }));
        return;
      }
      const sha = await sha256Hex(bytes);
      updateCurrentEditor((current) => ({ ...current, content: text, sha256: sha, phase: "editing" }));
    } catch (e) {
      updateCurrentEditor((current) => ({ ...current, phase: "error", error: errMessage(e) }));
    }
  }, [serverId]);

  const closeEditor = useCallback(() => {
    if (editor?.dirty) {
      setDirtyCloseOpen(true);
      return;
    }
    setEditor(null);
  }, [editor]);
  const [dirtyCloseOpen, setDirtyCloseOpen] = useState(false);

  const saveEditor = useCallback(async () => {
    if (!editor || editor.phase === "saving" || editor.phase === "loading") return;
    const bytes = new TextEncoder().encode(editor.content);
    if (bytes.length > EDITOR_MAX_BYTES) {
      setEditor((prev) => prev ? { ...prev, phase: "error", error: `The edited content is ${fmtBytes(bytes.length)} — the editor saves up to ${fmtBytes(EDITOR_MAX_BYTES)}.` } : prev);
      return;
    }
    setEditor((prev) => prev ? { ...prev, phase: "saving", conflict: null, error: null } : prev);
    try {
      const params = editorSaveParams({ size: editor.entry.size, mtime: editor.entry.mtime, sha256: editor.sha256 });
      await api.sftp.save(serverId, editor.path, bytesToBase64(bytes), params);
      const newSha = await sha256Hex(bytes);
      // The remote mtime after an atomic rename is only knowable from a
      // fresh stat — never guessed (spec 05 §4.2 identity contract).
      let identity = savedIdentityFallback(bytes.length, newSha, Date.now() / 1000);
      try {
        const st = await api.sftp.stat(serverId, editor.path);
        identity = { size: st.entry.size, mtime: st.entry.mtime, sha256: newSha };
      } catch { /* fallback identity above is honest about size + hash */ }
      setEditor((prev) => prev ? {
        ...prev,
        entry: { ...prev.entry, size: identity.size, mtime: identity.mtime },
        sha256: newSha,
        dirty: false,
        phase: "editing",
        conflict: null,
        error: null,
      } : prev);
      refreshAfterMutation(rpParent(editor.path));
    } catch (e) {
      const message = errMessage(e);
      if (isConflictError(message)) {
        setEditor((prev) => prev ? { ...prev, phase: "editing", conflict: message } : prev);
      } else {
        setEditor((prev) => prev ? { ...prev, phase: "editing", error: message } : prev);
      }
    }
  }, [editor, serverId, refreshAfterMutation]);

  const reloadEditor = useCallback(async () => {
    if (!editor) return;
    // A reload must re-capture the remote identity: the old entry's
    // size/mtime are stale the moment the server file changed.
    try {
      const st = await api.sftp.stat(serverId, editor.path);
      await openEditor(st.entry, editor.path);
      setEditor((prev) => prev ? { ...prev, conflict: null, error: null, dirty: false } : prev);
    } catch (e) {
      setEditor((prev) => prev ? { ...prev, conflict: null, error: errMessage(e) } : prev);
    }
  }, [editor, serverId, openEditor]);

  const discardEditorAndClose = useCallback(() => {
    setDirtyCloseOpen(false);
    setEditor(null);
  }, []);

  // Warn before the app window closes with unsaved changes.
  useEffect(() => {
    if (!editor?.dirty) return;
    const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [editor?.dirty]);

  // --- mutations ---------------------------------------------------------------

  const doMkdir = useCallback(async (name: string) => {
    const validation = validateLeafName(name);
    if (validation) throw new Error(validation);
    await api.sftp.mkdir(serverId, rpJoin(dirRef.current.path, rpFromUtf8(name)));
    setDialog(null);
    refreshAfterMutation(dirRef.current.path);
  }, [serverId, refreshAfterMutation]);

  const doRename = useCallback(async (entry: SftpEntry, name: string) => {
    const validation = validateLeafName(name);
    if (validation) throw new Error(validation);
    const parent = rpParent(rpJoin(dirRef.current.path, entry.name));
    await api.sftp.rename(serverId, rpJoin(dirRef.current.path, entry.name), rpJoin(parent, rpFromUtf8(name)));
    setDialog(null);
    refreshAfterMutation(dirRef.current.path);
  }, [serverId, refreshAfterMutation]);

  const doChmod = useCallback(async (entry: SftpEntry, mode: number) => {
    await api.sftp.chmod(serverId, rpJoin(dirRef.current.path, entry.name), mode);
    setDialog(null);
    refreshAfterMutation(dirRef.current.path);
  }, [serverId, refreshAfterMutation]);

  const doDelete = useCallback(async (entries: SftpEntry[], recursive: boolean) => {
    const parent = dirRef.current.path;
    let asyncStarted = false;
    for (const entry of entries) {
      const result = await api.sftp.rm(serverId, rpJoin(parent, entry.name), recursive);
      if ("op_id" in result) {
        asyncStarted = true;
        watchTransfer(result.op_id);
      }
    }
    setDialog(null);
    setSelection(emptySelection());
    if (!asyncStarted) refreshAfterMutation(parent);
  }, [serverId, refreshAfterMutation, watchTransfer]);

  const doUnzip = useCallback(async (entry: SftpEntry) => {
    const zipPath = rpJoin(dirRef.current.path, entry.name);
    const dest = rpJoin(rpParent(zipPath), rpStem(zipPath));
    const started = await api.sftp.unzip(serverId, zipPath, dest);
    watchTransfer(started.op_id);
    setDialog(null);
  }, [serverId, refreshAfterMutation, watchTransfer]);

  const doFolderSize = useCallback(async (entry: SftpEntry) => {
    const key = entryKey(entry);
    const path = rpJoin(dirRef.current.path, entry.name);
    setSizes((prev) => new Map(prev).set(key, { size: null, loading: true, error: null }));
    try {
      const r = await api.sftp.folderSize(serverId, path);
      setSizes((prev) => new Map(prev).set(key, { size: r.size, loading: false, error: null }));
    } catch (e) {
      setSizes((prev) => new Map(prev).set(key, { size: null, loading: false, error: errMessage(e) }));
    }
  }, [serverId]);

  const cancelBackendTransfer = useCallback(async (transfer: SftpTransfer) => {
    if (transfer.status !== "queued" && transfer.status !== "running") return;
    await api.sftp.cancel(serverId, transfer.id);
    setPollingTransfers(true);
  }, [serverId]);

  // --- drag & drop -------------------------------------------------------------

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  }, []);

  const onDrop = useCallback((e: React.DragEvent, targetDir?: RemotePath) => {
    e.preventDefault();
    setDropTarget(null);
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;
    handleFiles(files, targetDir ?? dirRef.current.path);
  }, [handleFiles]);

  // --- render ------------------------------------------------------------------

  const isEmpty = !dir.loading && !dir.refreshing && displayedEntries.length === 0 && !dir.error;
  const showTruncated = dir.listing.truncated && !dir.loading;
  const showDrawer = transfers.length > 0 || uploads.jobs.length > 0;

  return (
    <div
      className="fs-workspace"
      onKeyDown={onKeyDown}
      onDragOver={onDragOver}
      onDrop={(e) => onDrop(e)}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        hidden
        onChange={(e) => { if (e.target.files) handleFiles(e.target.files, dirRef.current.path); e.target.value = ""; }}
      />
      {directoryUploadSupported() && (
        <input
          ref={dirInputRef}
          type="file"
          multiple
          // @ts-expect-error webkitdirectory is the WebView directory picker
          webkitdirectory=""
          hidden
          onChange={(e) => { if (e.target.files) handleFiles(e.target.files, dirRef.current.path); e.target.value = ""; }}
        />
      )}

      <div className="fs-panes">
        <section className="fs-browser-surface fs-local-pane" aria-label="Local file browser">
          <header className="fs-pane-header">
            <div className="fs-pane-identity">
              <span className="fs-pane-icon" aria-hidden><Laptop size={17} /></span>
              <div>
                <span className="fs-location-label">This Mac</span>
                <strong>Local files</strong>
              </div>
            </div>
            <div className="fs-pane-header-actions">
              {local.path && localParent(local.path) !== local.path && (
                <button type="button" className="fs-icon-btn" title="Open parent local folder" aria-label="Open parent local folder" onClick={() => void loadLocal(localParent(local.path!))}>
                  <ArrowUp size={14} />
                </button>
              )}
              {local.path && (
                <button type="button" className="fs-icon-btn" title="Refresh local folder" aria-label="Refresh local folder" onClick={() => void loadLocal(local.path!)} disabled={local.loading}>
                  <RefreshCw size={14} className={local.loading ? "fs-spin" : ""} />
                </button>
              )}
              <Button size="xs" variant="outline" onClick={() => void chooseLocalFolder()}>Choose folder</Button>
            </div>
          </header>
          <div className="fs-pane-path" title={local.path ?? "No local folder selected"}>
            <span className="fs-path-led" aria-hidden />
            <code>{local.path ?? "Select a local folder to browse"}</code>
          </div>

          {selectedLocalEntries.some((entry) => entry.kind === "file") && (
            <div className="fs-pane-transfer-bar">
              <span>{selectedLocalEntries.filter((entry) => entry.kind === "file").length} selected</span>
              <Button size="xs" onClick={() => setDialog({ kind: "uploadLocal", entries: selectedLocalEntries.filter((entry) => entry.kind === "file") })}>
                Upload to remote <ArrowRight size={13} />
              </Button>
            </div>
          )}

          <div className="fs-pane-body">
            {!local.path ? (
              <div className="fs-pane-empty">
                <Laptop size={24} aria-hidden />
                <strong>Choose your working folder</strong>
                <p>Choose where local browsing starts. You can then move through folders on this Mac.</p>
                <Button size="sm" onClick={() => void chooseLocalFolder()}>Choose local folder</Button>
              </div>
            ) : local.loading && local.entries.length === 0 ? (
              <OarsLoadingState compact title="Reading local folder" detail="Oars is listing files on this Mac." />
            ) : local.error ? (
              <div className="fs-pane-empty fs-pane-error" role="alert">
                <AlertTriangle size={20} />
                <strong>Local folder unavailable</strong>
                <p>{local.error}</p>
                <Button size="xs" variant="outline" onClick={() => void chooseLocalFolder()}>Choose another folder</Button>
              </div>
            ) : local.entries.length === 0 ? (
              <div className="fs-pane-empty"><FolderOpen size={22} /><strong>This local folder is empty</strong></div>
            ) : (
              <div className="fs-pane-list" role="listbox" aria-multiselectable="true" aria-label="Local files">
                <div className="fs-pane-columns" aria-hidden><span>Name</span><span>Size</span><span>Modified</span></div>
                {local.entries.map((entry) => {
                  const selected = local.selected.includes(entry.path);
                  return (
                    <button
                      type="button"
                      key={entry.path}
                      className={`fs-pane-row ${selected ? "selected" : ""}`}
                      role="option"
                      aria-selected={selected}
                      onClick={(event) => toggleLocalEntry(entry, event.metaKey || event.ctrlKey)}
                      onDoubleClick={() => { if (entry.kind === "dir") void loadLocal(entry.path); }}
                    >
                      <span className="fs-pane-name">
                        <FileIcon entry={{ name: rpFromUtf8(entry.name), display: entry.name, kind: entry.kind, size: entry.size, mtime: entry.mtime, mode: "", uid: 0, gid: 0, link_target: null }} />
                        <span><strong>{entry.name}</strong><small>{kindLabel(entry.kind)}</small></span>
                      </span>
                      <span>{entry.kind === "dir" ? "—" : fmtBytes(entry.size)}</span>
                      <span>{fmtTime(entry.mtime)}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          {local.truncated && <div className="fs-pane-note">Only the first 5,000 local entries are shown.</div>}
        </section>

        <section className="fs-browser-surface fs-remote-pane" aria-label="Remote file browser">
          <header className="fs-pane-header">
            <div className="fs-pane-identity">
              <span className="fs-pane-icon" aria-hidden><FolderOpen size={17} /></span>
              <div>
                <span className="fs-location-label">Connected server</span>
                <strong>Remote files</strong>
              </div>
            </div>
            <div className="fs-pane-header-actions">
              {rpSerialize(dir.path) !== rpSerialize(ROOT) && (
                <button type="button" className="fs-icon-btn" title="Open parent remote folder" aria-label="Open parent remote folder" onClick={() => { setSelection(emptySelection()); loadDir(serverId, rpParent(dir.path)); }}>
                  <ArrowUp size={14} />
                </button>
              )}
              <button
                type="button"
                className="fs-icon-btn"
                title={showHidden ? "Hide hidden files" : "Show hidden files"}
                aria-label={showHidden ? "Hide hidden files" : "Show hidden files"}
                aria-pressed={showHidden}
                onClick={() => setShowHidden((value) => !value)}
              >
                {showHidden ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
              <button type="button" className="fs-icon-btn" title="Refresh remote folder" aria-label="Refresh remote folder" onClick={() => loadDir(serverId, dir.path)} disabled={dir.loading}>
                <RefreshCw size={14} className={dir.loading || dir.refreshing ? "fs-spin" : ""} />
              </button>
              <Button size="xs" variant="outline" onClick={() => fileInputRef.current?.click()} disabled={dir.loading}>Upload files</Button>
            </div>
          </header>
          <div className="fs-pane-path" title={rpDisplay(dir.path)}>
            <span className="fs-path-led fs-path-led-remote" aria-hidden />
            <code>{rpDisplay(dir.path)}</code>
            <div className="fs-pane-path-actions">
              {directoryUploadSupported() && (
                <button type="button" className="fs-icon-btn" title="Upload a folder" aria-label="Upload a folder" onClick={() => dirInputRef.current?.click()} disabled={dir.loading}><FolderInput size={14} /></button>
              )}
              <button type="button" className="fs-icon-btn" title="New remote folder" aria-label="New remote folder" onClick={() => setDialog({ kind: "mkdir" })} disabled={dir.loading}><FolderPlus size={14} /></button>
              {onNavigateToDeploy && <button type="button" className="fs-icon-btn" title="Add application from an archive" aria-label="Add application" onClick={onNavigateToDeploy}><FileArchive size={14} /></button>}
            </div>
          </div>

          {selectedEntries.length > 0 && (
            <div className="fs-pane-transfer-bar fs-remote-transfer-bar" role="toolbar" aria-label={`${selectedEntries.length} selected`}>
              <span>{selectedEntries.length} selected</span>
              <div className="fs-selection-actions">
                <Button size="xs" onClick={() => void downloadPaths(selectedEntries)}><ArrowDownToLine /> {local.path ? "Download to local" : selectedEntries.length === 1 ? "Download" : "Download ZIP"}</Button>
                {selectedEntries.length === 1 && selectedEntries[0].kind === "file" && <Button size="xs" variant="ghost" onClick={() => openEditor(selectedEntries[0], rpJoin(dir.path, selectedEntries[0].name))}><Pencil /> Edit</Button>}
                {selectedEntries.length === 1 && selectedEntries[0].kind === "dir" && <Button size="xs" variant="ghost" onClick={() => void doFolderSize(selectedEntries[0])}><HardDrive /> Size</Button>}
                {selectedEntries.length === 1 && isZipEntry(selectedEntries[0]) && <Button size="xs" variant="ghost" onClick={() => setDialog({ kind: "unzip", entry: selectedEntries[0] })}><FileArchive /> Expand</Button>}
                <Button size="xs" variant="ghost" onClick={() => setDialog({ kind: "rename", entry: selectedEntries[0] })} disabled={selectedEntries.length !== 1}><Pencil /> Rename</Button>
                <Button size="xs" variant="ghost" onClick={() => setDialog({ kind: "chmod", entry: selectedEntries[0] })} disabled={selectedEntries.length !== 1}><HardDrive /> Permissions</Button>
                <Button size="xs" variant="ghost" onClick={() => void copyPath(selectedEntries[0])} disabled={selectedEntries.length !== 1}><Copy /> Copy path</Button>
                <Button size="xs" variant="destructive" onClick={() => setDialog({ kind: "delete", entries: selectedEntries })}><Trash2 /> Delete</Button>
              </div>
            </div>
          )}

          {dir.error && (
            <div className="fs-error-banner" role="alert">
              <AlertTriangle size={15} />
              <span>{dir.error}</span>
              <button type="button" className="fs-error-dismiss" aria-label="Dismiss" onClick={() => setDir((previous) => ({ ...previous, error: null }))}><X size={13} /></button>
            </div>
          )}

          <div className="fs-pane-body">
            {dir.loading && dir.listing.entries.length === 0 ? (
              <OarsLoadingState compact title="Reading remote folder" detail="Oars is listing files on the connected server." />
            ) : isEmpty ? (
              <div className="fs-pane-empty">
                <FolderOpen size={22} aria-hidden />
                <strong>This remote folder is empty</strong>
                <p>Drop files here or use Upload files to copy content to this server.</p>
              </div>
            ) : (
              <div className="fs-pane-list" role="listbox" aria-multiselectable="true" aria-label="Remote files">
                <div className="fs-pane-columns" aria-hidden><span>Name</span><span>Size</span><span>Modified</span></div>
                {displayedEntries.map((entry) => {
                  const key = entryKey(entry);
                  const selected = selectionHas(selection, key);
                  const sizeInfo = sizes.get(key);
                  const size = entry.kind === "dir"
                    ? sizeInfo?.loading
                      ? "Measuring…"
                      : sizeInfo?.error
                        ? "Unavailable"
                        : sizeInfo?.size != null
                          ? fmtBytes(sizeInfo.size)
                          : "—"
                    : fmtBytes(entry.size);
                  return (
                    <button
                      type="button"
                      key={key}
                      className={`fs-pane-row ${selected ? "selected" : ""} ${dropTarget === key ? "drop" : ""}`}
                      role="option"
                      aria-selected={selected}
                      onClick={(event) => onRowClick(event, entry)}
                      onKeyDown={(event) => onRowKeyDown(event, entry)}
                      onDoubleClick={() => void openEntry(entry, dir.path)}
                      onDragOver={(event) => { event.preventDefault(); setDropTarget(entry.kind === "dir" ? key : null); }}
                      onDragLeave={() => setDropTarget((target) => target === key ? null : target)}
                      onDrop={(event) => { if (entry.kind === "dir") onDrop(event, rpJoin(dir.path, entry.name)); }}
                    >
                      <span className="fs-pane-name">
                        <FileIcon entry={entry} />
                        <span>
                          <strong>{entry.display}</strong>
                          <small>{kindLabel(entry.kind)}{entry.mode ? ` · ${entry.mode}` : ""}{entry.link_target ? ` · → ${entry.link_target}` : ""}</small>
                        </span>
                      </span>
                      <span title={sizeInfo?.error ?? undefined}>{size}</span>
                      <span>{fmtTime(entry.mtime)}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          {showTruncated && <div className="fs-pane-note">Only the first 5,000 remote entries are shown.</div>}
        </section>
      </div>

      {showDrawer && (
        <TransferDrawer
          transfers={transfers}
          uploads={uploads.jobs}
          onCancelUpload={cancelUpload}
          onCancelTransfer={cancelBackendTransfer}
        />
      )}

      {/* --- dialogs ---------------------------------------------------------- */}
      {dialog?.kind === "mkdir" && (
        <MkdirDialog
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async (name) => { try { await doMkdir(name); } catch (e) { throw new Error(errMessage(e)); } }}
        />
      )}
      {dialog?.kind === "rename" && (
        <RenameDialog
          entry={dialog.entry}
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async (name) => { try { await doRename(dialog.entry, name); } catch (e) { throw new Error(errMessage(e)); } }}
        />
      )}
      {dialog?.kind === "chmod" && (
        <ChmodDialog
          entry={dialog.entry}
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async (mode) => { try { await doChmod(dialog.entry, mode); } catch (e) { throw new Error(errMessage(e)); } }}
        />
      )}
      {dialog?.kind === "delete" && (
        <DeleteDialog
          entries={dialog.entries}
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async (recursive) => { try { await doDelete(dialog.entries, recursive); } catch (e) { throw new Error(errMessage(e)); } }}
        />
      )}
      {dialog?.kind === "unzip" && (
        <UnzipDialog
          entry={dialog.entry}
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async () => { try { await doUnzip(dialog.entry); } catch (e) { throw new Error(errMessage(e)); } }}
        />
      )}
      {dialog?.kind === "upload" && (
        <UploadDialog
          intents={dialog.intents}
          parent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async () => { await startUploads(dialog.intents, dir.path); setDialog(null); }}
        />
      )}
      {dialog?.kind === "uploadLocal" && (
        <LocalUploadDialog
          entries={dialog.entries}
          remoteParent={dir.path}
          onCancel={() => setDialog(null)}
          onConfirm={async () => { await startLocalUploads(dialog.entries); setDialog(null); }}
        />
      )}

      {/* --- editor ----------------------------------------------------------- */}
      {editor && (
        <EditorModal
          editor={editor}
          onClose={closeEditor}
          onSave={() => void saveEditor()}
          onReload={() => void reloadEditor()}
          onDiscard={discardEditorAndClose}
          onCancelDiscard={() => setDirtyCloseOpen(false)}
          onDismissConflict={() => setEditor((prev) => prev ? { ...prev, conflict: null } : prev)}
          dirtyCloseOpen={dirtyCloseOpen}
          onChange={(content) => setEditor((prev) => prev ? { ...prev, content, dirty: true } : prev)}
        />
      )}
    </div>
  );
}

// --- transfer drawer ----------------------------------------------------------

function TransferDrawer({
  transfers,
  uploads,
  onCancelUpload,
  onCancelTransfer,
}: {
  transfers: SftpTransfer[];
  uploads: UploadJob[];
  onCancelUpload: (job: UploadJob) => void;
  onCancelTransfer: (transfer: SftpTransfer) => void;
}) {
  const rows = useMemo(() => {
    const uploadIds = new Set(uploads.map((u) => u.transferId));
    const uploadRows = uploads
      .filter((u) => uploadActive(u) || u.status === "done" || u.status === "failed" || u.status === "canceled")
      .map((u) => ({
        id: u.transferId,
        kind: "upload",
        path: u.display,
        bytes: u.bytesSent,
        total: u.total,
        status: u.status as SftpTransferStatus,
        error: u.error,
        upload: u,
        backend: undefined as SftpTransfer | undefined,
      }));
    const backendRows = transfers
      .filter((t) => !uploadIds.has(t.id))
      .map((t) => ({ ...t, path: transferDisplay(t.path), upload: undefined as UploadJob | undefined, backend: t }));
    return [...uploadRows, ...backendRows];
  }, [transfers, uploads]);

  const running = rows.filter((r) => r.status === "queued" || r.status === "running").length;

  return (
    <div className="fs-drawer" aria-label="Transfers">
      <div className="fs-drawer-header">
        <span className="fs-drawer-title">
          Transfers {running > 0 && <span className="fs-drawer-count">{running} active</span>}
        </span>
        <span className="fs-drawer-hint">{rows.length} {rows.length === 1 ? "row" : "rows"}</span>
      </div>
      <div className="fs-drawer-rows">
        {rows.map((r) => (
          <div key={`${r.kind}-${r.id}`} className={`fs-transfer fs-transfer-${r.status}`}>
            <span className="fs-transfer-kind">
              {r.kind === "upload"
                ? <ArrowUp size={12} />
                : r.kind === "rm"
                  ? <Trash2 size={12} />
                  : r.kind === "unzip" || r.kind === "zip_download"
                    ? <FileArchive size={12} />
                    : <Download size={12} />}
            </span>
            <span className="fs-transfer-name" title={r.path}>{r.path}</span>
            <span className="fs-transfer-meta">
              <span className={`fs-transfer-state fs-transfer-state-${r.status}`}>
                <span className="fs-transfer-dot" aria-hidden />
                {r.status === "queued" ? "Queued" : r.status === "running" ? "Running" : r.status === "done" ? "Done" : r.status === "failed" ? "Failed" : "Canceled"}
              </span>
              <span>{r.status === "failed" ? r.error || "Transfer failed" : `${fmtBytes(r.bytes)} / ${fmtBytes(r.total)}`}</span>
            </span>
            <div className="fs-transfer-track" aria-hidden>
              <div
                className="fs-transfer-fill"
                style={{ "--fs-progress": r.total > 0 ? Math.min(1, r.bytes / r.total) : 0 } as React.CSSProperties}
              />
            </div>
            {r.upload && (r.status === "queued" || r.status === "running") && (
              <button type="button" className="fs-row-btn" title="Cancel upload" onClick={() => onCancelUpload(r.upload!)}>
                <X size={13} />
              </button>
            )}
            {r.backend && (r.status === "queued" || r.status === "running") && (
              <button type="button" className="fs-row-btn" title="Cancel transfer" onClick={() => onCancelTransfer(r.backend!)}>
                <X size={13} />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// --- editor modal -------------------------------------------------------------

function EditorModal({
  editor,
  onClose,
  onSave,
  onReload,
  onDiscard,
  onCancelDiscard,
  onDismissConflict,
  dirtyCloseOpen,
  onChange,
}: {
  editor: EditorState;
  onClose: () => void;
  onSave: () => void;
  onReload: () => void;
  onDiscard: () => void;
  onCancelDiscard: () => void;
  onDismissConflict: () => void;
  dirtyCloseOpen: boolean;
  onChange: (content: string) => void;
}) {
  const busy = editor.phase === "saving" || editor.phase === "loading";
  const [saveApprovalOpen, setSaveApprovalOpen] = useState(false);
  return (
    <div className="oars-modal-overlay" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div className="oars-modal fs-editor-modal" role="dialog" aria-modal="true" aria-labelledby="fs-editor-title">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon"><FileText /></span>
            <div style={{ minWidth: 0 }}>
              <h2 id="fs-editor-title">{editor.display}</h2>
              <p className="oars-modal-subtitle">
                {editor.dirty ? "Unsaved changes" : editor.phase === "editing" ? "Text file" : ""}
                {editor.dirty && editor.phase === "editing" ? " — " : ""}
                {editor.entry.size > 0 && `opened ${fmtBytes(editor.entry.size)} · ${fmtTime(editor.entry.mtime)}`}
              </p>
            </div>
            <Button variant="ghost" size="icon-sm" className="oars-modal-close" onClick={onClose} disabled={busy} aria-label="Close editor"><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body fs-editor-body">
          {editor.conflict && (
            <div className="fs-conflict-banner" role="alert">
              <AlertTriangle size={15} />
              <div>
                <strong>This file changed on the server since you opened it.</strong>
                <p>{editor.conflict.replace(/^conflict:\s*/, "")}</p>
                <div className="fs-conflict-actions">
                  <Button size="xs" variant="default" onClick={onReload}>Reload from server</Button>
                  <Button size="xs" variant="ghost" onClick={onDismissConflict}>Cancel</Button>
                </div>
              </div>
            </div>
          )}
          {editor.error && (
            <div className="fs-editor-error" role="alert">
              <XCircle size={15} />
              <span>{editor.error}</span>
            </div>
          )}
          {editor.phase === "loading" ? (
            <OarsLoadingState compact title="Reading file" detail="Oars is loading the file content in 64 KB chunks." />
          ) : editor.phase === "error" ? (
            <div className="fs-editor-error-state">
              <p className="muted">{editor.error}</p>
              <Button size="sm" variant="outline" onClick={onClose}>Close</Button>
            </div>
          ) : (
            <textarea
              className="fs-editor-textarea"
              value={editor.content}
              onChange={(e) => onChange(e.target.value)}
              spellCheck={false}
              autoFocus
              aria-label="File content"
            />
          )}
        </div>
        {editor.phase !== "error" && (
          <footer className="oars-modal-actions">
            <div className="oars-modal-actions-left">
              <span className="fs-editor-status">
                {editor.phase === "saving" ? "Saving…" : editor.dirty ? `${fmtBytes(new TextEncoder().encode(editor.content).length)} · unsaved` : "Saved"}
              </span>
            </div>
            <div className="oars-modal-actions-right">
              <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>Close</Button>
              <Button variant="default" size="sm" onClick={() => setSaveApprovalOpen(true)} disabled={busy || !editor.dirty || editor.phase !== "editing"}>
                {editor.phase === "saving" ? <Loader2 size={14} className="fs-spin" /> : null}
                Save
              </Button>
            </div>
          </footer>
        )}
      </div>

      {dirtyCloseOpen && (
        <ApprovalDialog
          icon={<AlertTriangle />}
          iconClass="oars-modal-icon-danger"
          title="Discard unsaved changes?"
          subtitle={editor.display}
          labelledBy="fs-dirty-title"
          actions={
            <>
              <Button variant="ghost" onClick={onCancelDiscard}>Keep editing</Button>
              <Button variant="destructive" onClick={onDiscard}>Discard changes</Button>
            </>
          }
          onCancel={onCancelDiscard}
        >
          <p className="muted" style={{ margin: 0 }}>Your edits have not been saved to the server. Closing now loses them.</p>
        </ApprovalDialog>
      )}

      {saveApprovalOpen && (
        <ApprovalDialog
          icon={<FileText />}
          iconClass=""
          title="Save changes to this file?"
          subtitle={<MonoPath rp={editor.path} />}
          labelledBy="fs-editor-save-title"
          busy={busy}
          onCancel={() => setSaveApprovalOpen(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setSaveApprovalOpen(false)} disabled={busy}>Keep editing</Button>
              <Button onClick={() => { setSaveApprovalOpen(false); onSave(); }} disabled={busy}>Save to server</Button>
            </>
          }
        >
          <p className="fs-dialog-explainer">Replace the remote file only if it still matches the version you opened.</p>
          <div className="fs-save-facts">
            <span>Remote file</span>
            <MonoPath rp={editor.path} />
            <span>New size</span>
            <strong>{fmtBytes(new TextEncoder().encode(editor.content).length)}</strong>
          </div>
        </ApprovalDialog>
      )}
    </div>
  );
}

// --- approval dialogs ---------------------------------------------------------

function MkdirDialog({ parent, onCancel, onConfirm }: { parent: RemotePath; onCancel: () => void; onConfirm: (name: string) => Promise<void> }) {
  const [name, setName] = useState("");
  const { busy, error, run } = useDialogAction();
  const nameError = validateLeafName(name.trim());
  const submit = async () => {
    if (nameError || busy) return;
    await run(() => onConfirm(name.trim()));
  };
  return (
    <ApprovalDialog
      icon={<FolderPlus />}
      iconClass=""
      title="New folder"
      subtitle={<>in <MonoPath rp={parent} /></>}
      labelledBy="fs-mkdir-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={Boolean(nameError) || busy}>Create folder</Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Create one folder inside the current remote location.</p>
      <div className="fs-dialog-target">
        <span>Will create</span>
        <MonoPath rp={name.trim() && !nameError ? rpJoin(parent, rpFromUtf8(name.trim())) : parent} />
      </div>
      <label className="fs-field">
        <span>Folder name</span>
        <input
          className="fs-input"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void submit(); }}
          placeholder="e.g. backups"
        />
      </label>
      {name.trim() && nameError && <div className="oars-form-error">{nameError}</div>}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function RenameDialog({ entry, parent, onCancel, onConfirm }: { entry: SftpEntry; parent: RemotePath; onCancel: () => void; onConfirm: (name: string) => Promise<void> }) {
  const [name, setName] = useState(entry.display);
  const { busy, error, run } = useDialogAction();
  const nameError = validateLeafName(name.trim());
  const submit = async () => {
    if (nameError || busy || name === entry.display) return;
    await run(() => onConfirm(name.trim()));
  };
  return (
    <ApprovalDialog
      icon={<Pencil />}
      iconClass=""
      title="Rename"
      subtitle={<>in <MonoPath rp={parent} /></>}
      labelledBy="fs-rename-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={Boolean(nameError) || name === entry.display || busy}>Rename</Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Change this item’s name without moving it out of the current folder.</p>
      <div className="fs-dialog-target">
        <span>Current item</span>
        <MonoPath rp={rpJoin(parent, entry.name)} />
        <span>New identity</span>
        <MonoPath rp={name.trim() && !nameError ? rpJoin(parent, rpFromUtf8(name.trim())) : parent} />
      </div>
      <label className="fs-field">
        <span>New name for <code className="fs-mono-path">{entry.display}</code></span>
        <input
          className="fs-input"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void submit(); }}
        />
      </label>
      {name.trim() && nameError && <div className="oars-form-error">{nameError}</div>}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function ChmodDialog({ entry, parent, onCancel, onConfirm }: { entry: SftpEntry; parent: RemotePath; onCancel: () => void; onConfirm: (mode: number) => Promise<void> }) {
  const [mode, setMode] = useState(() => permissionStringToOctal(entry.mode));
  const { busy, error, run } = useDialogAction();
  const modeValue = parseInt(mode, 8);
  const valid = /^[0-7]{1,4}$/.test(mode) && modeValue >= 0 && modeValue <= 0o7777;
  const submit = async () => {
    if (!valid || busy) return;
    await run(() => onConfirm(modeValue));
  };
  return (
    <ApprovalDialog
      icon={<HardDrive />}
      iconClass=""
      title="Change permissions"
      subtitle={<>on <MonoPath rp={rpJoin(parent, entry.name)} /></>}
      labelledBy="fs-chmod-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={!valid || busy}>Apply permissions</Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Apply POSIX permission bits to this remote item.</p>
      <label className="fs-field">
        <span>Permission bits (octal)</span>
        <input
          className="fs-input fs-input-mono"
          autoFocus
          value={mode}
          onChange={(e) => setMode(e.target.value.replace(/[^0-7]/g, "").slice(0, 4))}
          onKeyDown={(e) => { if (e.key === "Enter") void submit(); }}
          placeholder="644"
        />
      </label>
      {valid && <p className="muted" style={{ margin: 0 }}>Will apply: {modeString(modeValue)}</p>}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function modeString(mode: number): string {
  const chars = ["r", "w", "x"];
  let out = "";
  for (let g = 0; g < 3; g++) {
    for (let b = 0; b < 3; b++) {
      out += (mode >> ((2 - g) * 3 + (2 - b))) & 1 ? chars[b] : "-";
    }
  }
  if (mode & 0o4000) out = out.slice(0, 2) + (out[2] === "x" ? "s" : "S") + out.slice(3);
  if (mode & 0o2000) out = out.slice(0, 5) + (out[5] === "x" ? "s" : "S") + out.slice(6);
  if (mode & 0o1000) out = out.slice(0, 8) + (out[8] === "x" ? "t" : "T");
  return out;
}

function DeleteDialog({ entries, parent, onCancel, onConfirm }: { entries: SftpEntry[]; parent: RemotePath; onCancel: () => void; onConfirm: (recursive: boolean) => Promise<void> }) {
  const [confirmText, setConfirmText] = useState("");
  const { busy, error, run } = useDialogAction();
  const hasDir = entries.some((e) => e.kind === "dir");
  const recursive = hasDir || entries.length > 1;
  const single = entries.length === 1 ? entries[0] : null;
  const confirmName = single ? single.display : `${entries.length} items`;
  const needsTyping = hasDir;
  const ready = !needsTyping || confirmText === confirmName;
  const submit = async () => {
    if (!ready || busy) return;
    await run(() => onConfirm(recursive));
  };
  return (
    <ApprovalDialog
      icon={<Trash2 />}
      iconClass="oars-modal-icon-danger"
      title={needsTyping ? "Permanently delete this folder?" : `Delete ${entries.length > 1 ? `${entries.length} items` : "this item"}?`}
      subtitle={<>from <MonoPath rp={parent} /></>}
      labelledBy="fs-delete-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button variant="destructive" onClick={() => void submit()} disabled={!ready || busy}>Delete {recursive ? "recursively" : ""}</Button>
        </>
      }
    >
      <ul className="fs-delete-list">
        {entries.slice(0, 8).map((e) => (
          <li key={entryKey(e)}><FileIcon entry={e} size={13} /> {e.display}{e.kind === "dir" ? "/" : ""}</li>
        ))}
        {entries.length > 8 && <li className="muted">…and {entries.length - 8} more</li>}
      </ul>
      {needsTyping ? (
        <label className="fs-field">
          <span>Type <strong>{confirmName}</strong> to confirm — this cannot be undone.</span>
          <input className="fs-input" autoFocus value={confirmText} onChange={(e) => setConfirmText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void submit(); }} />
        </label>
      ) : (
        <p className="muted" style={{ margin: 0 }}>This cannot be undone. {hasDir ? "Folder contents are removed recursively." : ""}</p>
      )}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function UnzipDialog({ entry, parent, onCancel, onConfirm }: { entry: SftpEntry; parent: RemotePath; onCancel: () => void; onConfirm: () => Promise<void> }) {
  const { busy, error, run } = useDialogAction();
  const zipPath = rpJoin(parent, entry.name);
  const dest = rpJoin(rpParent(zipPath), rpStem(zipPath));
  const submit = async () => {
    if (busy) return;
    await run(onConfirm);
  };
  return (
    <ApprovalDialog
      icon={<FileArchive />}
      iconClass=""
      title="Expand ZIP archive"
      subtitle={<>from <MonoPath rp={zipPath} /></>}
      labelledBy="fs-unzip-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={busy}>Expand here</Button>
        </>
      }
    >
      <div className="fs-unzip-preview">
        <p className="muted" style={{ margin: 0 }}>The archive contents are extracted into a new folder next to the archive:</p>
        <MonoPath rp={dest} />
        <p className="muted" style={{ margin: 0 }}>Nothing is overwritten — the extraction refuses existing paths, and the archive is validated before anything is written.</p>
      </div>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function UploadDialog({ intents, parent, onCancel, onConfirm }: { intents: UploadIntent[]; parent: RemotePath; onCancel: () => void; onConfirm: () => Promise<void> }) {
  const totalBytes = intents.reduce((n, i) => n + i.file.size, 0);
  const { busy, error, run } = useDialogAction();
  const submit = async () => {
    if (busy) return;
    await run(onConfirm);
  };
  return (
    <ApprovalDialog
      icon={<Upload />}
      iconClass=""
      title={`Upload ${intents.length} ${intents.length === 1 ? "file" : "files"}?`}
      subtitle={<>to <MonoPath rp={parent} /></>}
      labelledBy="fs-upload-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={busy}>Start upload</Button>
        </>
      }
    >
      <p className="muted" style={{ margin: 0 }}>
        {intents.length} {intents.length === 1 ? "file" : "files"} · {fmtBytes(totalBytes)} total.
        {intents.some((i) => i.relativePath) ? " Folder structure is preserved." : ""}
      </p>
      <ul className="fs-upload-list">
        {intents.slice(0, 6).map((i, idx) => (
          <li key={idx}><FileIcon entry={{ name: rpFromUtf8(i.file.name), display: i.file.name, kind: "file", size: i.file.size, mtime: 0, mode: "", uid: 0, gid: 0, link_target: null }} size={13} /> {i.file.name} <span className="muted">· {fmtBytes(i.file.size)}</span></li>
        ))}
        {intents.length > 6 && <li className="muted">…and {intents.length - 6} more</li>}
      </ul>
      <p className="muted" style={{ margin: 0 }}>An existing file with the same name is never overwritten — the upload fails instead.</p>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}

function LocalUploadDialog({ entries, remoteParent, onCancel, onConfirm }: { entries: LocalEntry[]; remoteParent: RemotePath; onCancel: () => void; onConfirm: () => Promise<void> }) {
  const totalBytes = entries.reduce((total, entry) => total + entry.size, 0);
  const { busy, error, run } = useDialogAction();
  return (
    <ApprovalDialog
      icon={<ArrowRight />}
      iconClass=""
      title={`Upload ${entries.length} local ${entries.length === 1 ? "file" : "files"}?`}
      subtitle={<>to <MonoPath rp={remoteParent} /></>}
      labelledBy="fs-local-upload-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={() => void run(onConfirm)} disabled={busy}>Upload to remote</Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Copy these files from the approved local folder into the current remote folder.</p>
      <div className="fs-dialog-target">
        <span>Destination</span>
        <MonoPath rp={remoteParent} />
        <span>Total</span>
        <strong>{fmtBytes(totalBytes)}</strong>
      </div>
      <ul className="fs-upload-list">
        {entries.slice(0, 8).map((entry) => <li key={entry.path}><FileText size={13} /> {entry.name} <span className="muted">· {fmtBytes(entry.size)}</span></li>)}
        {entries.length > 8 && <li className="muted">…and {entries.length - 8} more</li>}
      </ul>
      <p className="muted" style={{ margin: 0 }}>Existing remote targets are never overwritten.</p>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
