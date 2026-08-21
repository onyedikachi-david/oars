import { ArrowUp, Eye, EyeOff, FolderInput, FolderOpen, FolderPlus, RefreshCw, Rocket } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { emptySelection, type SelectionModel } from "../../../file-state";
import { ROOT, rpDisplay, rpParent, rpSerialize, type RemotePath } from "../../../sftp-path";
import { directoryUploadSupported } from "../../../transfer-model";

export interface FileListHeaderProps {
  serverId: string;
  dirPath: RemotePath;
  loading: boolean;
  refreshing: boolean;
  showHidden: boolean;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  dirInputRef: React.RefObject<HTMLInputElement | null>;
  onNavigateToDeploy?: () => void;
  onLoadDir: (serverId: string, path: RemotePath) => void;
  onSetSelection: (selection: SelectionModel) => void;
  onSetShowHidden: (updater: (val: boolean) => boolean) => void;
  onRequestMkdir: () => void;
}

export function FileListHeader({
  serverId,
  dirPath,
  loading,
  refreshing,
  showHidden,
  fileInputRef,
  dirInputRef,
  onNavigateToDeploy,
  onLoadDir,
  onSetSelection,
  onSetShowHidden,
  onRequestMkdir,
}: FileListHeaderProps) {
  const isRoot = rpSerialize(dirPath) === rpSerialize(ROOT);

  return (
    <>
      <header className="fs-pane-header">
        <div className="fs-pane-identity">
          <span className="fs-pane-icon" aria-hidden>
            <FolderOpen size={17} />
          </span>
          <div>
            <span className="fs-location-label">Connected server</span>
            <strong>Remote files</strong>
          </div>
        </div>
        <div className="fs-pane-header-actions">
          {!isRoot && (
            <button
              type="button"
              className="fs-icon-btn"
              title="Open parent remote folder"
              aria-label="Open parent remote folder"
              onClick={() => {
                onSetSelection(emptySelection());
                onLoadDir(serverId, rpParent(dirPath));
              }}
            >
              <ArrowUp size={14} />
            </button>
          )}
          <button
            type="button"
            className="fs-icon-btn"
            title={showHidden ? "Hide hidden files" : "Show hidden files"}
            aria-label={showHidden ? "Hide hidden files" : "Show hidden files"}
            aria-pressed={showHidden}
            onClick={() => onSetShowHidden((value) => !value)}
          >
            {showHidden ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
          <button
            type="button"
            className="fs-icon-btn"
            title="Refresh remote folder"
            aria-label="Refresh remote folder"
            onClick={() => onLoadDir(serverId, dirPath)}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading || refreshing ? "fs-spin" : ""} />
          </button>
          <Button
            size="xs"
            variant="outline"
            onClick={() => fileInputRef.current?.click()}
            disabled={loading}
          >
            Upload files
          </Button>
        </div>
      </header>

      <div className="fs-pane-path" title={rpDisplay(dirPath)}>
        <span className="fs-path-led fs-path-led-remote" aria-hidden />
        <code>{rpDisplay(dirPath)}</code>
        <div className="fs-pane-path-actions">
          {directoryUploadSupported() && (
            <button
              type="button"
              className="fs-icon-btn"
              title="Upload a folder"
              aria-label="Upload a folder"
              onClick={() => dirInputRef.current?.click()}
              disabled={loading}
            >
              <FolderInput size={14} />
            </button>
          )}
          <button
            type="button"
            className="fs-icon-btn"
            title="New remote folder"
            aria-label="New remote folder"
            onClick={onRequestMkdir}
            disabled={loading}
          >
            <FolderPlus size={14} />
          </button>
          {onNavigateToDeploy && (
            <button
              type="button"
              className="fs-icon-btn"
              title="Open applications in Deploy"
              aria-label="Open applications in Deploy"
              onClick={onNavigateToDeploy}
            >
              <Rocket size={14} />
            </button>
          )}
        </div>
      </div>
    </>
  );
}
