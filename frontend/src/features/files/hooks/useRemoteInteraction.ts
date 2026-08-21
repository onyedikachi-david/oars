import { useCallback } from "react";
import { api } from "../../../bridge";
import {
  emptySelection,
  selectionAll,
  selectionRange,
  selectionSelectOnly,
  selectionToggle,
  type SelectionModel,
} from "../../../file-state";
import {
  entryKey,
  rpJoin,
  rpSerialize,
  type RemotePath,
} from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { kindLabel } from "../formatters";

export interface UseRemoteInteractionParams {
  serverId: string;
  selection: SelectionModel;
  setSelection: (selection: SelectionModel | ((curr: SelectionModel) => SelectionModel)) => void;
  displayedKeysRef: React.RefObject<string[]>;
  selectedEntriesRef: React.RefObject<SftpEntry[]>;
  selectionRef: React.RefObject<SelectionModel>;
  dirPathRef: React.RefObject<RemotePath>;
  loadDir: (serverId: string, path: RemotePath) => Promise<void>;
  onOpenFile: (entry: SftpEntry, path: RemotePath) => void;
  onRequestDelete: (entries: SftpEntry[]) => void;
  onDropFiles: (files: FileList | File[], targetDir?: RemotePath) => void;
  setDropTarget: (key: string | null) => void;
  setDirError: (err: string) => void;
  cacheDir: (pathKey: string, entries: SftpEntry[], truncated: boolean) => void;
}

export function useRemoteInteraction({
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
}: UseRemoteInteractionParams) {
  const onRowClick = useCallback((e: React.MouseEvent, entry: SftpEntry) => {
    const key = entryKey(entry);
    if (e.shiftKey) {
      setSelection((sel) => selectionRange(sel, displayedKeysRef.current ?? [], key));
    } else if (e.metaKey || e.ctrlKey) {
      setSelection((sel) => selectionToggle(sel, key));
    } else {
      setSelection(selectionSelectOnly(selectionRef.current ?? emptySelection(), key));
    }
  }, [displayedKeysRef, selectionRef, setSelection]);

  const openEntry = useCallback(
    async (entry: SftpEntry, parent: RemotePath) => {
      const path = rpJoin(parent, entry.name);
      if (entry.kind === "dir") {
        setSelection(emptySelection());
        void loadDir(serverId, path);
        return;
      }
      if (entry.kind === "file") {
        onOpenFile(entry, path);
        return;
      }
      if (entry.kind === "symlink") {
        try {
          const r = await api.sftp.ls(serverId, path);
          setSelection(emptySelection());
          cacheDir(rpSerialize(path), r.entries, r.truncated);
          void loadDir(serverId, path);
        } catch {
          onOpenFile(entry, path);
        }
        return;
      }
      setDirError(`This entry type (${kindLabel(entry.kind)}) cannot be opened.`);
    },
    [serverId, loadDir, onOpenFile, setSelection, cacheDir, setDirError],
  );

  const onRowKeyDown = useCallback(
    (e: React.KeyboardEvent, entry: SftpEntry) => {
      const key = entryKey(entry);
      if (e.key === "Enter") {
        e.preventDefault();
        e.stopPropagation();
        if (dirPathRef.current) void openEntry(entry, dirPathRef.current);
      } else if (e.key === " ") {
        e.preventDefault();
        e.stopPropagation();
        if (e.shiftKey) {
          setSelection((sel) => selectionRange(sel, displayedKeysRef.current ?? [], key));
        } else if (e.metaKey || e.ctrlKey) {
          setSelection((sel) => selectionToggle(sel, key));
        } else {
          setSelection((sel) => selectionToggle(sel, key));
        }
      } else if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        e.stopPropagation();
        onRequestDelete([entry]);
      }
    },
    [dirPathRef, openEntry, onRequestDelete, setSelection, displayedKeysRef],
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
      if (e.key === "Escape") {
        if (selection.keys.length > 0) setSelection(emptySelection());
        return;
      }
      if (e.key === "a" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        if (displayedKeysRef.current) setSelection(selectionAll(displayedKeysRef.current));
        return;
      }
      if (e.key === "Enter") {
        const first = selectedEntriesRef.current?.[0];
        if (first && dirPathRef.current) void openEntry(first, dirPathRef.current);
        return;
      }
      if (e.key === "Delete" || e.key === "Backspace") {
        const sel = selectedEntriesRef.current ?? [];
        if (sel.length > 0) {
          e.preventDefault();
          onRequestDelete(sel);
        }
      }
    },
    [selection.keys, displayedKeysRef, selectedEntriesRef, dirPathRef, openEntry, onRequestDelete, setSelection],
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent, targetDir?: RemotePath) => {
      e.preventDefault();
      setDropTarget(null);
      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;
      if (dirPathRef.current) onDropFiles(files, targetDir ?? dirPathRef.current);
    },
    [dirPathRef, onDropFiles, setDropTarget],
  );

  return {
    onRowClick,
    openEntry,
    onRowKeyDown,
    onKeyDown,
    onDragOver,
    onDrop,
  };
}
