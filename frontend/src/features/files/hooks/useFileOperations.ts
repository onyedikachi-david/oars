import { useCallback } from "react";
import { api } from "../../../bridge";
import { emptySelection, type SelectionModel } from "../../../file-state";
import {
  rpDisplay,
  rpFromUtf8,
  rpJoin,
  rpParent,
  rpStem,
  validateLeafName,
  type RemotePath,
} from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import type { DialogState } from "../types";

export interface UseFileOperationsParams {
  serverId: string;
  dirPath: RemotePath;
  refreshAfterMutation: (path: RemotePath) => void;
  watchTransfer: (opId: number) => void;
  setDialog: (dialog: DialogState) => void;
  setSelection: (selection: SelectionModel) => void;
}

export function useFileOperations({
  serverId,
  dirPath,
  refreshAfterMutation,
  watchTransfer,
  setDialog,
  setSelection,
}: UseFileOperationsParams) {
  const copyPath = useCallback(
    async (entry: SftpEntry) => {
      const path = rpJoin(dirPath, entry.name);
      await navigator.clipboard.writeText(rpDisplay(path));
    },
    [dirPath],
  );

  const doMkdir = useCallback(
    async (name: string) => {
      const validation = validateLeafName(name);
      if (validation) throw new Error(validation);
      await api.sftp.mkdir(serverId, rpJoin(dirPath, rpFromUtf8(name)));
      setDialog(null);
      refreshAfterMutation(dirPath);
    },
    [serverId, dirPath, refreshAfterMutation, setDialog],
  );

  const doRename = useCallback(
    async (entry: SftpEntry, name: string) => {
      const validation = validateLeafName(name);
      if (validation) throw new Error(validation);
      const parent = rpParent(rpJoin(dirPath, entry.name));
      await api.sftp.rename(serverId, rpJoin(dirPath, entry.name), rpJoin(parent, rpFromUtf8(name)));
      setDialog(null);
      refreshAfterMutation(dirPath);
    },
    [serverId, dirPath, refreshAfterMutation, setDialog],
  );

  const doChmod = useCallback(
    async (entry: SftpEntry, mode: number) => {
      await api.sftp.chmod(serverId, rpJoin(dirPath, entry.name), mode);
      setDialog(null);
      refreshAfterMutation(dirPath);
    },
    [serverId, dirPath, refreshAfterMutation, setDialog],
  );

  const doDelete = useCallback(
    async (entries: SftpEntry[], recursive: boolean) => {
      const parent = dirPath;
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
    },
    [serverId, dirPath, refreshAfterMutation, watchTransfer, setSelection, setDialog],
  );

  const doUnzip = useCallback(
    async (entry: SftpEntry) => {
      const zipPath = rpJoin(dirPath, entry.name);
      const dest = rpJoin(rpParent(zipPath), rpStem(zipPath));
      const started = await api.sftp.unzip(serverId, zipPath, dest);
      watchTransfer(started.op_id);
      setDialog(null);
    },
    [serverId, dirPath, watchTransfer, setDialog],
  );

  return {
    copyPath,
    doMkdir,
    doRename,
    doChmod,
    doDelete,
    doUnzip,
  };
}
