import { useMemo } from "react";
import { ArrowUp, Download, FileArchive, Trash2, X } from "lucide-react";
import { uploadActive, type UploadJob } from "../../transfer-model";
import type { SftpTransfer, SftpTransferStatus } from "../../types";
import { fmtBytes, transferDisplay } from "./formatters";

export interface TransferDrawerProps {
  transfers?: SftpTransfer[];
  uploads?: UploadJob[];
  rows?: any[];
  queuedUploads?: number;
  onCancelUpload: (job: any) => void;
  onCancelTransfer: (transfer: any) => void;
}

export function TransferDrawer({
  transfers = [],
  uploads = [],
  rows: customRows,
  queuedUploads,
  onCancelUpload,
  onCancelTransfer,
}: TransferDrawerProps) {
  const computedRows = useMemo(() => {
    if (customRows) return customRows;
    const safeUploads = uploads ?? [];
    const safeTransfers = transfers ?? [];
    const uploadIds = new Set(safeUploads.map((u) => u.transferId));
    const uploadRows = safeUploads
      .filter((u) => uploadActive(u) || u.status === "done" || u.status === "failed" || u.status === "canceled")
      .map((u) => ({
        id: u.transferId,
        key: `upload-${u.transferId}`,
        label: u.display,
        kind: "upload",
        path: u.display,
        bytes: u.bytesSent,
        total: u.total,
        status: u.status as SftpTransferStatus,
        error: u.error,
        upload: u,
        backend: undefined as SftpTransfer | undefined,
      }));
    const backendRows = safeTransfers
      .filter((t) => !uploadIds.has(t.id))
      .map((t) => ({
        ...t,
        key: `backend-${t.id}`,
        label: transferDisplay(t.path),
        path: transferDisplay(t.path),
        upload: undefined as UploadJob | undefined,
        backend: t,
      }));
    return [...uploadRows, ...backendRows];
  }, [transfers, uploads, customRows]);

  const rows = customRows ?? computedRows;
  const running = rows.filter((r) => r.status === "queued" || r.status === "running").length;

  return (
    <div className="fs-drawer" aria-label="Transfers">
      <div className="fs-drawer-header">
        <span className="fs-drawer-title">
          Transfers {running > 0 && <span className="fs-drawer-count">{running} active</span>}
        </span>
        <span className="fs-drawer-hint">
          {rows.length} {rows.length === 1 ? "row" : "rows"}
        </span>
      </div>
      <div className="fs-drawer-rows">
        {rows.map((r) => (
          <div key={`${r.kind}-${r.id}`} className={`fs-transfer fs-transfer-${r.status}`}>
            <span className="fs-transfer-kind">
              {r.kind === "upload" ? (
                <ArrowUp size={12} />
              ) : r.kind === "rm" ? (
                <Trash2 size={12} />
              ) : r.kind === "unzip" || r.kind === "zip_download" ? (
                <FileArchive size={12} />
              ) : (
                <Download size={12} />
              )}
            </span>
            <span className="fs-transfer-name" title={r.path}>
              {r.path}
            </span>
            <span className="fs-transfer-meta">
              <span className={`fs-transfer-state fs-transfer-state-${r.status}`}>
                <span className="fs-transfer-dot" aria-hidden />
                {r.status === "queued"
                  ? "Queued"
                  : r.status === "running"
                    ? "Running"
                    : r.status === "done"
                      ? "Done"
                      : r.status === "failed"
                        ? "Failed"
                        : "Canceled"}
              </span>
              <span>
                {r.status === "failed"
                  ? r.error || "Transfer failed"
                  : `${fmtBytes(r.bytes)} / ${fmtBytes(r.total)}`}
              </span>
            </span>
            <div
              className="fs-transfer-track"
              role="progressbar"
              aria-valuenow={r.total > 0 ? Math.round((r.bytes / r.total) * 100) : 0}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Transfer progress for ${r.label || r.path || "file"}`}
              aria-valuetext={
                r.total > 0
                  ? `${Math.round((r.bytes / r.total) * 100)}% (${fmtBytes(r.bytes)} of ${fmtBytes(r.total)})`
                  : "Pending"
              }
            >
              <div
                className="fs-transfer-fill"
                style={{ "--fs-progress": r.total > 0 ? Math.min(1, r.bytes / r.total) : 0 } as React.CSSProperties}
              />
            </div>
            {r.upload && (r.status === "queued" || r.status === "running") && (
              <button
                type="button"
                className="fs-row-btn"
                title="Cancel upload"
                aria-label={`Cancel upload of ${r.label || r.path || "file"}`}
                onClick={() => onCancelUpload(r.upload ?? r)}
              >
                <X size={13} />
              </button>
            )}
            {r.backend && (r.status === "queued" || r.status === "running") && (
              <button
                type="button"
                className="fs-row-btn"
                title="Cancel transfer"
                aria-label={`Cancel transfer of ${r.label || r.path || "file"}`}
                onClick={() => onCancelTransfer(r.backend ?? r)}
              >
                <X size={13} />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
