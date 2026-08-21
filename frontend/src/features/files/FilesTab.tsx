import { useCallback, useRef, useState } from "react";
import type { RemotePath } from "../../sftp-path";
import { directoryUploadSupported, fileRelativePath } from "../../transfer-model";
import { FilesDialogHost } from "./dialogs/FilesDialogHost";
import { EditorModal } from "./EditorModal";
import { FileListPane } from "./FileListPane";
import { useFileEditor } from "./hooks/useFileEditor";
import { useFileOperations } from "./hooks/useFileOperations";
import { useFileTransfers } from "./hooks/useFileTransfers";
import { useLocalDirectory } from "./hooks/useLocalDirectory";
import { useRemoteDirectory } from "./hooks/useRemoteDirectory";
import { LocalListPane } from "./LocalListPane";
import { TransferDrawer } from "./TransferDrawer";
import type { DialogState, FilesTabProps, UploadIntent } from "./types";

export function FilesTab({ serverId, onNavigateToDeploy }: FilesTabProps) {
  const [dialog, setDialog] = useState<DialogState>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);

  const {
    editor, dirtyCloseOpen, openEditor, closeEditor, saveEditor, reloadEditor,
    updateEditorContent, discardEditorAndClose, cancelDiscard,
  } = useFileEditor({ serverId, onRefreshAfterMutation: (path) => refreshAfterMutation(path) });

  const {
    transfers, uploads, startUploads, cancelUpload, startLocalUploads,
    downloadPaths, watchTransfer, cancelBackendTransfer,
  } = useFileTransfers({ serverId, onRefreshAfterMutation: (path) => refreshAfterMutation(path) });

  const { local, loadLocal, chooseLocalFolder, selectedLocalEntries, toggleLocalEntry } =
    useLocalDirectory(transfers);

  const handleFiles = useCallback((files: FileList | File[], _parent: RemotePath, relativeBase?: string) => {
    const intents: UploadIntent[] = Array.from(files).map((f) => ({
      file: f,
      relativePath: relativeBase !== undefined ? `${relativeBase}/${f.name}` : fileRelativePath(f),
    }));
    if (intents.length === 0) return;
    setDialog({ kind: "upload", intents });
  }, []);

  const {
    dir, selection, setSelection, showHidden, setShowHidden, sizes, dropTarget, setDropTarget,
    displayedEntries, selectedEntries, loadDir, refreshAfterMutation, onRowClick, onRowKeyDown,
    onKeyDown, openEntry, doFolderSize, onDragOver, onDrop,
  } = useRemoteDirectory({
    serverId,
    onOpenFile: (entry, path) => openEditor(entry, path),
    onRequestDelete: (entries) => setDialog({ kind: "delete", entries }),
    onDropFiles: (files, targetDir) => handleFiles(files, targetDir ?? dir.path),
  });

  const { copyPath, doMkdir, doRename, doChmod, doDelete, doUnzip } = useFileOperations({
    serverId, dirPath: dir.path, refreshAfterMutation, watchTransfer, setDialog, setSelection,
  });

  const showDrawer = transfers.length > 0 || uploads.jobs.length > 0;

  return (
    <div className="fs-workspace" onKeyDown={onKeyDown} onDragOver={onDragOver} onDrop={onDrop}>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        hidden
        onChange={(e) => {
          if (e.target.files) handleFiles(e.target.files, dir.path);
          e.target.value = "";
        }}
      />
      {directoryUploadSupported() && (
        <input
          ref={dirInputRef}
          type="file"
          multiple
          // @ts-expect-error webkitdirectory is the WebView directory picker
          webkitdirectory=""
          hidden
          onChange={(e) => {
            if (e.target.files) handleFiles(e.target.files, dir.path);
            e.target.value = "";
          }}
        />
      )}

      <div className="fs-panes">
        <LocalListPane
          local={local}
          selectedLocalEntries={selectedLocalEntries}
          onLoadLocal={loadLocal}
          onChooseFolder={chooseLocalFolder}
          onToggleEntry={toggleLocalEntry}
          onRequestUpload={(entries) => setDialog({ kind: "uploadLocal", entries })}
        />

        <FileListPane
          serverId={serverId}
          dir={dir}
          selection={selection}
          showHidden={showHidden}
          sizes={sizes}
          dropTarget={dropTarget}
          displayedEntries={displayedEntries}
          selectedEntries={selectedEntries}
          localPath={local.path}
          fileInputRef={fileInputRef}
          dirInputRef={dirInputRef}
          onNavigateToDeploy={onNavigateToDeploy}
          onLoadDir={loadDir}
          onSetSelection={setSelection}
          onSetShowHidden={setShowHidden}
          onClearError={() => {}}
          onRowClick={onRowClick}
          onRowKeyDown={onRowKeyDown}
          onOpenEntry={(entry, parent) => void openEntry(entry, parent)}
          onSetDropTarget={setDropTarget}
          onDrop={onDrop}
          onDownload={(entries) => void downloadPaths(entries, dir.path, local.path)}
          onOpenEditor={openEditor}
          onDoFolderSize={(entry) => void doFolderSize(entry)}
          onCopyPath={(entry) => void copyPath(entry)}
          onRequestMkdir={() => setDialog({ kind: "mkdir" })}
          onRequestRename={(entry) => setDialog({ kind: "rename", entry })}
          onRequestChmod={(entry) => setDialog({ kind: "chmod", entry })}
          onRequestDelete={(entries) => setDialog({ kind: "delete", entries })}
          onRequestUnzip={(entry) => setDialog({ kind: "unzip", entry })}
        />
      </div>

      {showDrawer && (
        <TransferDrawer
          transfers={transfers}
          uploads={uploads.jobs}
          onCancelUpload={cancelUpload}
          onCancelTransfer={cancelBackendTransfer}
        />
      )}

      <FilesDialogHost
        dialog={dialog}
        dirPath={dir.path}
        onClose={() => setDialog(null)}
        onMkdir={doMkdir}
        onRename={doRename}
        onChmod={doChmod}
        onDelete={doDelete}
        onUnzip={doUnzip}
        onStartUploads={startUploads}
        onStartLocalUploads={startLocalUploads}
      />

      {editor && (
        <EditorModal
          editor={editor}
          onClose={closeEditor}
          onSave={() => void saveEditor()}
          onReload={() => void reloadEditor()}
          onDiscard={discardEditorAndClose}
          onCancelDiscard={cancelDiscard}
          onDismissConflict={() => {}}
          dirtyCloseOpen={dirtyCloseOpen}
          onChange={updateEditorContent}
        />
      )}
    </div>
  );
}
