import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { api } from "../../../bridge";
import type { RemotePath } from "../../../sftp-path";
import {
  emptyUploadModel,
  MAX_CONCURRENT_UPLOADS,
  uploadActive,
  uploadDirectoryPaths,
  uploadJobFor,
  uploadReducer,
  type UploadJob,
} from "../../../transfer-model";
import type { LocalEntry, SftpEntry, SftpTransfer } from "../../../types";
import { errMessage } from "../formatters";
import type { UploadIntent } from "../types";
import { executeDownloadPaths, executeLocalUploads } from "./downloadTransport";
import { ensureRemoteDirectoryPath, uploadFileChunks } from "./uploadTransport";

export interface UseFileTransfersParams {
  serverId: string;
  onRefreshAfterMutation: (path: RemotePath) => void;
}

export function useFileTransfers({
  serverId,
  onRefreshAfterMutation,
}: UseFileTransfersParams) {
  const [transfers, setTransfers] = useState<SftpTransfer[]>([]);
  const [pollingTransfers, setPollingTransfers] = useState(false);
  const [uploads, dispatchUpload] = useReducer(uploadReducer, undefined, emptyUploadModel);

  const cancelledRef = useRef(new Set<number>());
  const observedFinalRef = useRef(new Set<number>());

  const anyUploadActive = useMemo(() => uploads.jobs.some(uploadActive), [uploads.jobs]);
  const anyTransferActive = useMemo(
    () => transfers.some((t) => t.status === "queued" || t.status === "running"),
    [transfers],
  );

  const watchTransfer = useCallback((opId: number) => {
    observedFinalRef.current.delete(opId);
    setPollingTransfers(true);
  }, []);

  // Transfer polling
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
        const newlyFinished = snap.transfers.filter(
          (t) =>
            (t.status === "done" || t.status === "failed" || t.status === "canceled") &&
            !observedFinalRef.current.has(t.id),
        );
        if (newlyFinished.length > 0) {
          for (const transfer of newlyFinished) observedFinalRef.current.add(transfer.id);
        }
        quietPolls = active ? 0 : quietPolls + 1;
        if (!active && !anyUploadActive && quietPolls >= 2) setPollingTransfers(false);
      } catch {
        // Keeps last snapshot
      }
    };

    void poll();
    timer = window.setInterval(poll, 800);
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [serverId, anyTransferActive, anyUploadActive, pollingTransfers]);

  // Server switch reset
  useEffect(() => {
    setTransfers([]);
    cancelledRef.current.clear();
    observedFinalRef.current.clear();
    setPollingTransfers(false);
  }, [serverId]);

  const runUpload = useCallback(
    async (job: UploadJob, currentRemotePath: RemotePath) => {
      const { transferId, serverId: server } = job;
      dispatchUpload({ type: "start", transferId });
      try {
        const completed = await uploadFileChunks(
          job,
          (id) => cancelledRef.current.has(id),
          (bytesSent) => dispatchUpload({ type: "progress", transferId, bytesSent }),
        );
        if (completed) {
          dispatchUpload({ type: "done", transferId });
          onRefreshAfterMutation(currentRemotePath);
        } else {
          dispatchUpload({ type: "canceled", transferId });
        }
      } catch (e) {
        await api.sftp.cancel(server, transferId).catch(() => {});
        dispatchUpload({ type: "failed", transferId, error: errMessage(e) });
      }
    },
    [onRefreshAfterMutation],
  );

  const startUploads = useCallback(
    async (intents: UploadIntent[], parent: RemotePath) => {
      const directories = uploadDirectoryPaths(
        parent,
        intents.map((intent) => intent.relativePath),
      );
      for (const directory of directories) await ensureRemoteDirectoryPath(serverId, directory);
      const jobs = intents.map((i) => uploadJobFor(serverId, parent, i.file, i.relativePath));
      for (const job of jobs) dispatchUpload({ type: "register", job });
      let index = 0;
      const workers = Array.from({ length: Math.min(MAX_CONCURRENT_UPLOADS, jobs.length) }, async () => {
        while (index < jobs.length) {
          const job = jobs[index++];
          await runUpload(job, parent);
        }
      });
      void Promise.all(workers);
    },
    [serverId, runUpload],
  );

  const cancelUpload = useCallback(
    async (jobOrId?: any) => {
      if (jobOrId == null) return;
      const transferId = typeof jobOrId === "number" ? jobOrId : (jobOrId.transferId ?? jobOrId.id);
      if (typeof transferId !== "number") return;
      const targetServer = typeof jobOrId === "object" && jobOrId?.serverId ? jobOrId.serverId : serverId;
      cancelledRef.current.add(transferId);
      dispatchUpload({ type: "canceled", transferId });
      await api.sftp.cancel(targetServer, transferId).catch(() => {});
    },
    [serverId],
  );

  const startLocalUploads = useCallback(
    async (entries: LocalEntry[], remoteParent: RemotePath) => {
      await executeLocalUploads(serverId, entries, remoteParent, watchTransfer);
    },
    [serverId, watchTransfer],
  );

  const downloadPaths = useCallback(
    async (entries: SftpEntry[], remoteParent: RemotePath, localFolder: string | null) => {
      await executeDownloadPaths(serverId, entries, remoteParent, localFolder, watchTransfer);
    },
    [serverId, watchTransfer],
  );

  const cancelBackendTransfer = useCallback(
    async (transferOrId: SftpTransfer | number) => {
      const id = typeof transferOrId === "number" ? transferOrId : transferOrId.id;
      const raw = typeof transferOrId === "object" && transferOrId !== null ? (transferOrId as unknown as Record<string, unknown>) : null;
      const targetServer =
        raw && typeof raw.serverId === "string"
          ? raw.serverId
          : raw && typeof raw.server_id === "string"
            ? raw.server_id
            : serverId;
      await api.sftp.cancel(targetServer, id);
      setTransfers((curr) =>
        curr.map((t) => (t.id === id ? { ...t, status: "canceled" } : t)),
      );
    },
    [serverId],
  );

  return {
    transfers,
    uploads,
    startUploads,
    cancelUpload,
    startLocalUploads,
    downloadPaths,
    watchTransfer,
    cancelBackendTransfer,
  };
}
