import type { RemotePath } from "../../../sftp-path";
import type { LocalEntry, SftpEntry } from "../../../types";
import { errMessage } from "../formatters";
import type { DialogState, UploadIntent } from "../types";
import { ChmodDialog } from "./ChmodDialog";
import { DeleteDialog } from "./DeleteDialog";
import { LocalUploadDialog } from "./LocalUploadDialog";
import { MkdirDialog } from "./MkdirDialog";
import { RenameDialog } from "./RenameDialog";
import { UnzipDialog } from "./UnzipDialog";
import { UploadDialog } from "./UploadDialog";

export interface FilesDialogHostProps {
  dialog: DialogState;
  dirPath: RemotePath;
  onClose: () => void;
  onMkdir: (name: string) => Promise<void>;
  onRename: (entry: SftpEntry, name: string) => Promise<void>;
  onChmod: (entry: SftpEntry, mode: number) => Promise<void>;
  onDelete: (entries: SftpEntry[], recursive: boolean) => Promise<void>;
  onUnzip: (entry: SftpEntry) => Promise<void>;
  onStartUploads: (intents: UploadIntent[], parent: RemotePath) => Promise<void>;
  onStartLocalUploads: (entries: LocalEntry[], parent: RemotePath) => Promise<void>;
}

export function FilesDialogHost({
  dialog,
  dirPath,
  onClose,
  onMkdir,
  onRename,
  onChmod,
  onDelete,
  onUnzip,
  onStartUploads,
  onStartLocalUploads,
}: FilesDialogHostProps) {
  if (!dialog) return null;

  return (
    <>
      {dialog.kind === "mkdir" && (
        <MkdirDialog
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async (name) => {
            try {
              await onMkdir(name);
            } catch (e) {
              throw new Error(errMessage(e));
            }
          }}
        />
      )}
      {dialog.kind === "rename" && (
        <RenameDialog
          entry={dialog.entry}
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async (name) => {
            try {
              await onRename(dialog.entry, name);
            } catch (e) {
              throw new Error(errMessage(e));
            }
          }}
        />
      )}
      {dialog.kind === "chmod" && (
        <ChmodDialog
          entry={dialog.entry}
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async (mode) => {
            try {
              await onChmod(dialog.entry, mode);
            } catch (e) {
              throw new Error(errMessage(e));
            }
          }}
        />
      )}
      {dialog.kind === "delete" && (
        <DeleteDialog
          entries={dialog.entries}
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async (recursive) => {
            try {
              await onDelete(dialog.entries, recursive);
            } catch (e) {
              throw new Error(errMessage(e));
            }
          }}
        />
      )}
      {dialog.kind === "unzip" && (
        <UnzipDialog
          entry={dialog.entry}
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async () => {
            try {
              await onUnzip(dialog.entry);
            } catch (e) {
              throw new Error(errMessage(e));
            }
          }}
        />
      )}
      {dialog.kind === "upload" && (
        <UploadDialog
          intents={dialog.intents}
          parent={dirPath}
          onCancel={onClose}
          onConfirm={async () => {
            await onStartUploads(dialog.intents, dirPath);
            onClose();
          }}
        />
      )}
      {dialog.kind === "uploadLocal" && (
        <LocalUploadDialog
          entries={dialog.entries}
          remoteParent={dirPath}
          onCancel={onClose}
          onConfirm={async () => {
            await onStartLocalUploads(dialog.entries, dirPath);
            onClose();
          }}
        />
      )}
    </>
  );
}
