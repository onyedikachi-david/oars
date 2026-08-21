import { ArrowDownToLine, Copy, FileArchive, HardDrive, Pencil, Trash2 } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { rpJoin, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { isZipEntry } from "../formatters";

export interface FileListToolbarProps {
  dirPath: RemotePath;
  selectedEntries: SftpEntry[];
  localPath: string | null;
  onDownload: (entries: SftpEntry[]) => void;
  onOpenEditor: (entry: SftpEntry, path: RemotePath) => void;
  onDoFolderSize: (entry: SftpEntry) => void;
  onRequestUnzip: (entry: SftpEntry) => void;
  onRequestRename: (entry: SftpEntry) => void;
  onRequestChmod: (entry: SftpEntry) => void;
  onCopyPath: (entry: SftpEntry) => void;
  onRequestDelete: (entries: SftpEntry[]) => void;
}

export function FileListToolbar({
  dirPath,
  selectedEntries,
  localPath,
  onDownload,
  onOpenEditor,
  onDoFolderSize,
  onRequestUnzip,
  onRequestRename,
  onRequestChmod,
  onCopyPath,
  onRequestDelete,
}: FileListToolbarProps) {
  if (selectedEntries.length === 0) return null;

  const isSingle = selectedEntries.length === 1;
  const first = selectedEntries[0];

  return (
    <div
      className="fs-pane-transfer-bar fs-remote-transfer-bar"
      role="toolbar"
      aria-label={`${selectedEntries.length} selected`}
    >
      <span>{selectedEntries.length} selected</span>
      <div className="fs-selection-actions">
        <Button size="xs" onClick={() => onDownload(selectedEntries)}>
          <ArrowDownToLine />{" "}
          {localPath
            ? "Download to local"
            : isSingle
              ? "Download"
              : "Download ZIP"}
        </Button>
        {isSingle && first.kind === "file" && (
          <Button
            size="xs"
            variant="ghost"
            onClick={() => onOpenEditor(first, rpJoin(dirPath, first.name))}
          >
            <Pencil /> Edit
          </Button>
        )}
        {isSingle && first.kind === "dir" && (
          <Button size="xs" variant="ghost" onClick={() => onDoFolderSize(first)}>
            <HardDrive /> Size
          </Button>
        )}
        {isSingle && isZipEntry(first) && (
          <Button size="xs" variant="ghost" onClick={() => onRequestUnzip(first)}>
            <FileArchive /> Expand
          </Button>
        )}
        <Button
          size="xs"
          variant="ghost"
          onClick={() => onRequestRename(first)}
          disabled={!isSingle}
        >
          <Pencil /> Rename
        </Button>
        <Button
          size="xs"
          variant="ghost"
          onClick={() => onRequestChmod(first)}
          disabled={!isSingle}
        >
          <HardDrive /> Permissions
        </Button>
        <Button
          size="xs"
          variant="ghost"
          onClick={() => onCopyPath(first)}
          disabled={!isSingle}
        >
          <Copy /> Copy path
        </Button>
        <Button size="xs" variant="destructive" onClick={() => onRequestDelete(selectedEntries)}>
          <Trash2 /> Delete
        </Button>
      </div>
    </div>
  );
}
