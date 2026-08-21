import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, ArrowUp, FolderOpen, Laptop, RefreshCw } from "lucide-react";
import { OarsLoadingState } from "../../components/OarsLoadingState";
import { Button } from "../../components/ui/button";
import { localParent } from "../../local-path";
import { rpFromUtf8 } from "../../sftp-path";
import type { LocalEntry } from "../../types";
import { FileIcon } from "./components/FileIcon";
import { fmtBytes, fmtTime, kindLabel } from "./formatters";
import type { LocalPaneState } from "./types";

export interface LocalListPaneProps {
  local: LocalPaneState;
  selectedLocalEntries: LocalEntry[];
  onLoadLocal: (path: string) => Promise<void>;
  onChooseFolder: () => Promise<void>;
  onToggleEntry: (entry: LocalEntry, additive: boolean) => void;
  onRequestUpload: (entries: LocalEntry[]) => void;
}

export function LocalListPane({
  local,
  selectedLocalEntries,
  onLoadLocal,
  onChooseFolder,
  onToggleEntry,
  onRequestUpload,
}: LocalListPaneProps) {
  const [focusedIndex, setFocusedIndex] = useState(0);
  const fileEntries = selectedLocalEntries.filter((entry) => entry.kind === "file");

  useEffect(() => {
    setFocusedIndex((prev) => {
      if (local.entries.length === 0) return 0;
      if (prev >= local.entries.length) return local.entries.length - 1;
      return prev;
    });
  }, [local.entries.length]);

  const handleRowKeyDown = (event: React.KeyboardEvent, entry: LocalEntry, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(local.entries.length - 1, index + 1);
      setFocusedIndex(next);
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[next]?.focus();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedIndex(prev);
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
      const last = local.entries.length - 1;
      setFocusedIndex(last);
      const btns = document.querySelectorAll<HTMLButtonElement>(".fs-pane-list .fs-pane-row");
      btns[last]?.focus();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (entry.kind === "dir") {
        void onLoadLocal(entry.path);
      } else {
        onToggleEntry(entry, event.metaKey || event.ctrlKey);
      }
      return;
    }
    if (event.key === " ") {
      event.preventDefault();
      onToggleEntry(entry, event.metaKey || event.ctrlKey);
      return;
    }
  };

  return (
    <section className="fs-browser-surface fs-local-pane" aria-label="Local file browser">
      <header className="fs-pane-header">
        <div className="fs-pane-identity">
          <span className="fs-pane-icon" aria-hidden>
            <Laptop size={17} />
          </span>
          <div>
            <span className="fs-location-label">This Mac</span>
            <strong>Local files</strong>
          </div>
        </div>
        <div className="fs-pane-header-actions">
          <Button
            size="xs"
            variant="outline"
            onClick={() => void onChooseFolder()}
            disabled={local.loading}
          >
            Change folder…
          </Button>
          <Button
            size="icon-xs"
            variant="ghost"
            aria-label="Refresh local folder"
            onClick={() => { if (local.path) void onLoadLocal(local.path); }}
            disabled={!local.path || local.loading}
          >
            <RefreshCw className={local.loading ? "fs-spin" : ""} />
          </Button>
        </div>
      </header>

      <div className="fs-pane-path" title={local.path || "No local folder selected"}>
        <span className="fs-path-led" aria-hidden />
        <code>{local.path || "No folder selected"}</code>
        <div className="fs-pane-path-actions">
          <Button
            size="icon-xs"
            variant="ghost"
            aria-label="Go up to parent folder"
            onClick={() => { if (local.path) void onLoadLocal(localParent(local.path)); }}
            disabled={!local.path || local.path === "/" || local.loading}
          >
            <ArrowUp />
          </Button>
        </div>
      </div>

      {fileEntries.length > 0 && (
        <div className="fs-pane-transfer-bar">
          <span>
            {fileEntries.length} file{fileEntries.length === 1 ? "" : "s"} selected
          </span>
          <Button size="xs" onClick={() => onRequestUpload(fileEntries)}>
            <ArrowRight /> Upload to remote
          </Button>
        </div>
      )}

      <div className="fs-pane-body">
        {local.path === "" ? (
          <div className="fs-pane-empty">
            <FolderOpen size={22} />
            <strong>No local folder selected</strong>
            <p>Choose where local browsing starts. You can then move through folders on this Mac.</p>
            <Button size="sm" onClick={() => void onChooseFolder()}>
              Choose local folder
            </Button>
          </div>
        ) : local.loading && local.entries.length === 0 ? (
          <OarsLoadingState
            compact
            title="Reading local folder"
            detail="Oars is listing files on this Mac."
          />
        ) : local.error ? (
          <div className="fs-pane-empty fs-pane-error" role="alert">
            <AlertTriangle size={20} />
            <strong>Local folder unavailable</strong>
            <p>{local.error}</p>
            <Button size="xs" variant="outline" onClick={() => void onChooseFolder()}>
              Choose another folder
            </Button>
          </div>
        ) : local.entries.length === 0 ? (
          <div className="fs-pane-empty">
            <FolderOpen size={22} />
            <strong>This local folder is empty</strong>
          </div>
        ) : (
          <div
            className="fs-pane-list"
            role="listbox"
            aria-multiselectable="true"
            aria-label="Local files"
          >
            <div className="fs-pane-columns" aria-hidden>
              <span>Name</span>
              <span>Size</span>
              <span>Modified</span>
            </div>
            {local.entries.map((entry, index) => {
              const selected = local.selected.includes(entry.path);
              const isFocused = index === focusedIndex || (focusedIndex === -1 && index === 0);
              return (
                <button
                  type="button"
                  key={entry.path}
                  tabIndex={isFocused ? 0 : -1}
                  className={`fs-pane-row ${selected ? "selected" : ""}`}
                  role="option"
                  aria-selected={selected}
                  onFocus={() => setFocusedIndex(index)}
                  onClick={(event) => onToggleEntry(entry, event.metaKey || event.ctrlKey)}
                  onKeyDown={(event) => handleRowKeyDown(event, entry, index)}
                  onDoubleClick={() => {
                    if (entry.kind === "dir") void onLoadLocal(entry.path);
                  }}
                >
                  <span className="fs-pane-name">
                    <FileIcon
                      entry={{
                        name: rpFromUtf8(entry.name),
                        display: entry.name,
                        kind: entry.kind,
                        size: entry.size,
                        mtime: entry.mtime,
                        mode: "",
                        uid: 0,
                        gid: 0,
                        link_target: null,
                      }}
                    />
                    <span>
                      <strong>{entry.name}</strong>
                      <small>{kindLabel(entry.kind)}</small>
                    </span>
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
  );
}
