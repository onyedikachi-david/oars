import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, pickDirectory } from "../../../bridge";
import type { LocalEntry, SftpTransfer } from "../../../types";
import { errMessage } from "../formatters";
import type { LocalPaneState } from "../types";

export function useLocalDirectory(transfers: SftpTransfer[]) {
  const [local, setLocal] = useState<LocalPaneState>({
    path: null,
    entries: [],
    loading: false,
    error: null,
    truncated: false,
    selected: [],
  });

  const localObservedFinalRef = useRef(new Set<number>());

  const loadLocal = useCallback(async (path: string) => {
    setLocal((current) => ({ ...current, path, loading: true, error: null, selected: [] }));
    try {
      const result = await api.local.ls(path);
      setLocal((current) =>
        current.path === path
          ? {
              path,
              entries: result.entries,
              loading: false,
              error: null,
              truncated: result.truncated,
              selected: [],
            }
          : current,
      );
    } catch (cause) {
      setLocal((current) =>
        current.path === path
          ? { ...current, loading: false, error: errMessage(cause), selected: [] }
          : current,
      );
    }
  }, []);

  const chooseLocalFolder = useCallback(async () => {
    const path = await pickDirectory("Choose a local folder", local.path ?? undefined);
    if (path) await loadLocal(path);
  }, [local.path, loadLocal]);

  useEffect(() => {
    if (!local.path) return;
    const completedDownloads = transfers.filter(
      (transfer) =>
        (transfer.kind === "download" || transfer.kind === "zip_download") &&
        transfer.status === "done" &&
        !localObservedFinalRef.current.has(transfer.id),
    );
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

  const clearLocalSelection = useCallback(() => {
    setLocal((current) => ({ ...current, selected: [] }));
  }, []);

  return {
    local,
    loadLocal,
    chooseLocalFolder,
    selectedLocalEntries,
    toggleLocalEntry,
    clearLocalSelection,
  };
}
