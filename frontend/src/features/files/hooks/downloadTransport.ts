import { api, pickSaveFile } from "../../../bridge";
import { localJoin } from "../../../local-path";
import {
  rpDisplay,
  rpFromUtf8,
  rpJoin,
  type RemotePath,
} from "../../../sftp-path";
import type { LocalEntry, SftpEntry } from "../../../types";

export async function executeLocalUploads(
  serverId: string,
  entries: LocalEntry[],
  remoteParent: RemotePath,
  watchTransfer: (opId: number) => void,
): Promise<void> {
  for (const entry of entries) {
    const started = await api.sftp.uploadLocal(
      serverId,
      entry.path,
      rpJoin(remoteParent, rpFromUtf8(entry.name)),
    );
    watchTransfer(started.op_id);
  }
}

export async function executeDownloadPaths(
  serverId: string,
  entries: SftpEntry[],
  remoteParent: RemotePath,
  localFolder: string | null,
  watchTransfer: (opId: number) => void,
): Promise<void> {
  if (entries.length === 0) return;
  if (localFolder) {
    for (const entry of entries) {
      const started = await api.sftp.download(
        serverId,
        rpJoin(remoteParent, entry.name),
        localJoin(localFolder, entry.display),
      );
      watchTransfer(started.op_id);
    }
    return;
  }
  const isSingle = entries.length === 1;
  const first = entries[0];
  const defaultName = isSingle
    ? first.kind === "dir"
      ? `${first.display}.zip`
      : first.display
    : `${rpDisplay(remoteParent).replace(/[\/\\]/g, "_") || "archive"}.zip`;
  const chosen = await pickSaveFile(defaultName);
  if (!chosen) return;
  if (isSingle && first.kind !== "dir") {
    const started = await api.sftp.download(serverId, rpJoin(remoteParent, first.name), chosen);
    watchTransfer(started.op_id);
  } else {
    const sources = entries.map((e) => rpJoin(remoteParent, e.name));
    const started = await api.sftp.zipDownload(serverId, sources, chosen);
    watchTransfer(started.op_id);
  }
}
