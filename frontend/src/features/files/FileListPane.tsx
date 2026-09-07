import type { DirSnapshot, SelectionModel } from "../../file-state";
import type { RemotePath } from "../../sftp-path";
import type { SftpEntry } from "../../types";
import { FileListHeader } from "./components/FileListHeader";
import { FileListToolbar } from "./components/FileListToolbar";
import { FileListView } from "./components/FileListView";

export interface FileListPaneProps {
  serverId: string;
  dir: DirSnapshot;
  selection: SelectionModel;
  showHidden: boolean;
  sizes: Map<string, { size: number | null; loading: boolean; error: string | null }>;
  dropTarget: string | null;
  displayedEntries: SftpEntry[];
  selectedEntries: SftpEntry[];
  localPath: string | null;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  dirInputRef: React.RefObject<HTMLInputElement | null>;
  onNavigateToDeploy?: () => void;
  onLoadDir: (serverId: string, path: RemotePath) => void;
  onSetSelection: (selection: SelectionModel) => void;
  onSetShowHidden: (updater: (val: boolean) => boolean) => void;
  onClearError: () => void;
  onRowClick: (event: React.MouseEvent, entry: SftpEntry) => void;
  onRowKeyDown: (event: React.KeyboardEvent, entry: SftpEntry) => void;
  onOpenEntry: (entry: SftpEntry, parent: RemotePath) => void;
  onSetDropTarget: (key: string | null | ((curr: string | null) => string | null)) => void;
  onDrop: (event: React.DragEvent, targetDir?: RemotePath) => void;
  onDownload: (entries: SftpEntry[]) => void;
  onOpenEditor: (entry: SftpEntry, path: RemotePath) => void;
  onDoFolderSize: (entry: SftpEntry) => void;
  onCopyPath: (entry: SftpEntry) => void;
  onRequestMkdir: () => void;
  onRequestRename: (entry: SftpEntry) => void;
  onRequestChmod: (entry: SftpEntry) => void;
  onRequestDelete: (entries: SftpEntry[]) => void;
  onRequestUnzip: (entry: SftpEntry) => void;
}

export function FileListPane({
  serverId,
  dir,
  selection,
  showHidden,
  sizes,
  dropTarget,
  displayedEntries,
  selectedEntries,
  localPath,
  fileInputRef,
  dirInputRef,
  onNavigateToDeploy,
  onLoadDir,
  onSetSelection,
  onSetShowHidden,
  onClearError,
  onRowClick,
  onRowKeyDown,
  onOpenEntry,
  onSetDropTarget,
  onDrop,
  onDownload,
  onOpenEditor,
  onDoFolderSize,
  onCopyPath,
  onRequestMkdir,
  onRequestRename,
  onRequestChmod,
  onRequestDelete,
  onRequestUnzip,
}: FileListPaneProps) {
  return (
    <section className="fs-browser-surface fs-remote-pane" aria-label="Remote file browser">
      <FileListHeader
        serverId={serverId}
        dirPath={dir.path}
        loading={dir.loading}
        refreshing={dir.refreshing}
        showHidden={showHidden}
        fileInputRef={fileInputRef}
        dirInputRef={dirInputRef}
        onNavigateToDeploy={onNavigateToDeploy}
        onLoadDir={onLoadDir}
        onSetSelection={onSetSelection}
        onSetShowHidden={onSetShowHidden}
        onRequestMkdir={onRequestMkdir}
      />

      <FileListToolbar
        dirPath={dir.path}
        selectedEntries={selectedEntries}
        localPath={localPath}
        onDownload={onDownload}
        onOpenEditor={onOpenEditor}
        onDoFolderSize={onDoFolderSize}
        onRequestUnzip={onRequestUnzip}
        onRequestRename={onRequestRename}
        onRequestChmod={onRequestChmod}
        onCopyPath={onCopyPath}
        onRequestDelete={onRequestDelete}
      />

      <FileListView
        dir={dir}
        selection={selection}
        sizes={sizes}
        dropTarget={dropTarget}
        displayedEntries={displayedEntries}
        onClearError={onClearError}
        onRowClick={onRowClick}
        onRowKeyDown={onRowKeyDown}
        onOpenEntry={onOpenEntry}
        onSetDropTarget={onSetDropTarget}
        onDrop={onDrop}
      />
    </section>
  );
}
