import { useEffect, useState } from "react";
import { AlertTriangle, FolderOpen, X } from "lucide-react";
import { OarsLoadingState } from "../../../components/OarsLoadingState";
import { selectionHas, type DirSnapshot, type SelectionModel } from "../../../file-state";
import { entryKey, rpJoin, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { fmtBytes, fmtTime, kindLabel } from "../formatters";
import { FileIcon } from "./FileIcon";

export interface FileListViewProps {
  dir: DirSnapshot;
  selection: SelectionModel;
  sizes: Map<string, { size: number | null; loading: boolean; error: string | null }>;
  dropTarget: string | null;
  displayedEntries: SftpEntry[];
  onClearError: () => void;
  onRowClick: (event: React.MouseEvent, entry: SftpEntry) => void;
  onRowKeyDown: (event: React.KeyboardEvent, entry: SftpEntry) => void;
  onOpenEntry: (entry: SftpEntry, parent: RemotePath) => void;
  onSetDropTarget: (key: string | null | ((curr: string | null) => string | null)) => void;
  onDrop: (event: React.DragEvent, targetDir?: RemotePath) => void;
}

export function FileListView({
  dir,
  selection,
  sizes,
  dropTarget,
  displayedEntries,
  onClearError,
  onRowClick,
  onRowKeyDown,
  onOpenEntry,
  onSetDropTarget,
  onDrop,
}: FileListViewProps) {
  const [focusedIndex, setFocusedIndex] = useState(0);
  const isEmpty = !dir.loading && !dir.refreshing && displayedEntries.length === 0 && !dir.error;
  const showTruncated = dir.listing.truncated && !dir.loading;

  useEffect(() => {
    setFocusedIndex((prev) => {
      if (displayedEntries.length === 0) return 0;
      if (prev >= displayedEntries.length) return displayedEntries.length - 1;
      return prev;
    });
  }, [displayedEntries.length]);

  const handleRowKeyDown = (event: React.KeyboardEvent, entry: SftpEntry, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(displayedEntries.length - 1, index + 1);
      setFocusedIndex(next);
      if (event.shiftKey) {
        onRowClick({ shiftKey: true, metaKey: false, ctrlKey: false } as any, displayedEntries[next]);
      }
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[next]?.focus();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedIndex(prev);
      if (event.shiftKey) {
        onRowClick({ shiftKey: true, metaKey: false, ctrlKey: false } as any, displayedEntries[prev]);
      }
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[prev]?.focus();
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setFocusedIndex(0);
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[0]?.focus();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      const last = displayedEntries.length - 1;
      setFocusedIndex(last);
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[last]?.focus();
      return;
    }
    onRowKeyDown(event, entry);
  };

  return (
    <>
      {dir.error && (
        <div className="fs-error-banner" role="alert">
          <AlertTriangle size={15} />
          <span>{dir.error}</span>
          <button
            type="button"
            className="fs-error-dismiss"
            aria-label="Dismiss"
            onClick={onClearError}
          >
            <X size={13} />
          </button>
        </div>
      )}

      <div className="fs-pane-body">
        {dir.loading && dir.listing.entries.length === 0 ? (
          <OarsLoadingState
            compact
            title="Reading remote folder"
            detail="Oars is listing files on the connected server."
          />
        ) : isEmpty ? (
          <div className="fs-pane-empty">
            <FolderOpen size={22} aria-hidden />
            <strong>This remote folder is empty</strong>
            <p>Drop files here or use Upload files to copy content to this server.</p>
          </div>
        ) : (
          <div
            className="fs-pane-list"
            role="listbox"
            aria-multiselectable="true"
            aria-label="Remote files"
          >
            <div className="fs-pane-columns" aria-hidden>
              <span>Name</span>
              <span>Size</span>
              <span>Modified</span>
            </div>
            {displayedEntries.map((entry, index) => {
              const key = entryKey(entry);
              const selected = selectionHas(selection, key);
              const sizeInfo = sizes.get(key);
              const isFocused = index === focusedIndex || (focusedIndex === -1 && index === 0);
              const size =
                entry.kind === "dir"
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
                  tabIndex={isFocused ? 0 : -1}
                  className={`fs-pane-row ${selected ? "selected" : ""} ${dropTarget === key ? "drop" : ""}`}
                  role="option"
                  aria-selected={selected}
                  onFocus={() => setFocusedIndex(index)}
                  onClick={(event) => onRowClick(event, entry)}
                  onKeyDown={(event) => handleRowKeyDown(event, entry, index)}
                  onDoubleClick={() => onOpenEntry(entry, dir.path)}
                  onDragOver={(event) => {
                    event.preventDefault();
                    onSetDropTarget(entry.kind === "dir" ? key : null);
                  }}
                  onDragLeave={() =>
                    onSetDropTarget((target) => (target === key ? null : target))
                  }
                  onDrop={(event) => {
                    if (entry.kind === "dir") onDrop(event, rpJoin(dir.path, entry.name));
                  }}
                >
                  <span className="fs-pane-name">
                    <FileIcon entry={entry} />
                    <span>
                      <strong>{entry.display}</strong>
                      <small>
                        {kindLabel(entry.kind)}
                        {entry.mode ? ` · ${entry.mode}` : ""}
                        {entry.link_target ? ` · → ${entry.link_target}` : ""}
                      </small>
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
    </>
  );
}
