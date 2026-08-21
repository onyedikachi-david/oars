import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../../bridge";
import {
  DirCache,
  emptySelection,
  emptySnapshot,
  isCurrentDirRequest,
  type DirSnapshot,
  type SelectionModel,
} from "../../../file-state";
import {
  entryHidden,
  entryKey,
  ROOT,
  rpJoin,
  rpSerialize,
  type RemotePath,
} from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { errMessage } from "../formatters";
import { useRemoteInteraction } from "./useRemoteInteraction";

export interface UseRemoteDirectoryParams {
  serverId: string;
  onOpenFile: (entry: SftpEntry, path: RemotePath) => void;
  onRequestDelete: (entries: SftpEntry[]) => void;
  onDropFiles: (files: FileList | File[], targetDir?: RemotePath) => void;
}

export function useRemoteDirectory({
  serverId,
  onOpenFile,
  onRequestDelete,
  onDropFiles,
}: UseRemoteDirectoryParams) {
  const [dir, setDir] = useState<DirSnapshot>(() => emptySnapshot(serverId, ROOT));
  const [selection, setSelection] = useState<SelectionModel>(emptySelection);
  const [showHidden, setShowHidden] = useState(false);
  const [sizes, setSizes] = useState<
    Map<string, { size: number | null; loading: boolean; error: string | null }>
  >(new Map());
  const [dropTarget, setDropTarget] = useState<string | null>(null);

  const generationRef = useRef(0);
  const cacheRef = useRef(new DirCache());

  const loadDir = useCallback(async (server: string, path: RemotePath, background = false) => {
    const pathKey = rpSerialize(path);
    const generation = ++generationRef.current;
    const token = { generation, serverId: server, pathKey };
    const now = Date.now();
    const cached = cacheRef.current.get(server, pathKey, now);

    if (cached) {
      setDir((prev) => ({
        ...prev, serverId: server, path, pathKey, listing: cached,
        loading: false, refreshing: !background, error: null, loadedAt: now,
      }));
      if (background) return;
    } else {
      setDir((prev) => ({
        ...prev, serverId: server, path, pathKey,
        listing: prev.serverId === server && prev.pathKey === pathKey ? prev.listing : { entries: [], truncated: false },
        loading: true, refreshing: false, error: null,
      }));
    }

    try {
      const r = await api.sftp.ls(server, path);
      if (!isCurrentDirRequest(token, generationRef.current, server, pathKey)) return;
      cacheRef.current.set(server, pathKey, { entries: r.entries, truncated: r.truncated }, Date.now());
      setDir({
        serverId: server, path, pathKey, listing: { entries: r.entries, truncated: r.truncated },
        loading: false, refreshing: false, error: null, loadedAt: Date.now(),
      });
    } catch (e) {
      if (!isCurrentDirRequest(token, generationRef.current, server, pathKey)) return;
      setDir((prev) => ({ ...prev, serverId: server, path, pathKey, loading: false, refreshing: false, error: errMessage(e) }));
    }
  }, []);

  useEffect(() => {
    cacheRef.current.clear();
    setSizes(new Map());
    setSelection(emptySelection());
    setDropTarget(null);
    void loadDir(serverId, ROOT);
  }, [serverId, loadDir]);

  const refreshAfterMutation = useCallback((path: RemotePath) => {
    cacheRef.current.invalidate(serverId, rpSerialize(path));
    if (rpSerialize(dir.path) === rpSerialize(path)) {
      void loadDir(serverId, path, true);
    }
  }, [serverId, dir.path, loadDir]);

  const displayedEntries = useMemo(
    () => (showHidden ? dir.listing.entries : dir.listing.entries.filter((e) => !entryHidden(e))),
    [dir.listing.entries, showHidden],
  );

  const displayedKeys = useMemo(() => displayedEntries.map(entryKey), [displayedEntries]);
  const displayedKeysRef = useRef(displayedKeys);
  displayedKeysRef.current = displayedKeys;

  const selectedEntries = useMemo(() => {
    const set = new Set(selection.keys);
    return displayedEntries.filter((e) => set.has(entryKey(e)));
  }, [displayedEntries, selection.keys]);

  const selectedEntriesRef = useRef(selectedEntries);
  selectedEntriesRef.current = selectedEntries;
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const dirPathRef = useRef(dir.path);
  dirPathRef.current = dir.path;

  const doFolderSize = useCallback(async (entry: SftpEntry) => {
    const key = entryKey(entry);
    const path = rpJoin(dirPathRef.current, entry.name);
    setSizes((prev) => new Map(prev).set(key, { size: null, loading: true, error: null }));
    try {
      const r = await api.sftp.folderSize(serverId, path);
      setSizes((prev) => new Map(prev).set(key, { size: r.size, loading: false, error: null }));
    } catch (e) {
      setSizes((prev) => new Map(prev).set(key, { size: null, loading: false, error: errMessage(e) }));
    }
  }, [serverId]);

  const setDirError = useCallback((err: string) => {
    setDir((prev) => ({ ...prev, error: err }));
  }, []);

  const cacheDir = useCallback((pathKey: string, entries: SftpEntry[], truncated: boolean) => {
    cacheRef.current.set(serverId, pathKey, { entries, truncated }, Date.now());
  }, [serverId]);

  const { onRowClick, openEntry, onRowKeyDown, onKeyDown, onDragOver, onDrop } = useRemoteInteraction({
    serverId,
    selection,
    setSelection,
    displayedKeysRef,
    selectedEntriesRef,
    selectionRef,
    dirPathRef,
    loadDir,
    onOpenFile,
    onRequestDelete,
    onDropFiles,
    setDropTarget,
    setDirError,
    cacheDir,
  });

  return {
    dir, selection, setSelection, showHidden, setShowHidden, sizes, dropTarget, setDropTarget,
    displayedEntries, selectedEntries, loadDir, refreshAfterMutation, onRowClick, onRowKeyDown,
    onKeyDown, openEntry, doFolderSize, onDragOver, onDrop,
  };
}
