import { AlertTriangle, FileText } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { RemotePath } from "../../../sftp-path";
import { MonoPath } from "../components/MonoPath";
import { fmtBytes } from "../formatters";
import { ApprovalDialog } from "./ApprovalDialog";

export interface EditorDiscardDialogProps {
  open: boolean;
  display: string;
  onCancel: () => void;
  onDiscard: () => void;
}

export function EditorDiscardDialog({ open, display, onCancel, onDiscard }: EditorDiscardDialogProps) {
  if (!open) return null;
  return (
    <ApprovalDialog
      icon={<AlertTriangle />}
      iconClass="oars-modal-icon-danger"
      title="Discard unsaved changes?"
      subtitle={display}
      labelledBy="fs-dirty-title"
      actions={
        <>
          <Button variant="ghost" onClick={onCancel}>
            Keep editing
          </Button>
          <Button variant="destructive" onClick={onDiscard}>
            Discard changes
          </Button>
        </>
      }
      onCancel={onCancel}
    >
      <p className="muted" style={{ margin: 0 }}>
        Your edits have not been saved to the server. Closing now loses them.
      </p>
    </ApprovalDialog>
  );
}

export interface EditorSaveDialogProps {
  open: boolean;
  path: RemotePath;
  contentLength: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

export function EditorSaveDialog({
  open,
  path,
  contentLength,
  busy,
  onCancel,
  onConfirm,
}: EditorSaveDialogProps) {
  if (!open) return null;
  return (
    <ApprovalDialog
      icon={<FileText />}
      iconClass=""
      title="Save changes to this file?"
      subtitle={<MonoPath rp={path} />}
      labelledBy="fs-editor-save-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Keep editing
          </Button>
          <Button onClick={onConfirm} disabled={busy}>
            Save to server
          </Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Replace the remote file only if it still matches the version you opened.</p>
      <div className="fs-save-facts">
        <span>Remote file</span>
        <MonoPath rp={path} />
        <span>New size</span>
        <strong>{fmtBytes(contentLength)}</strong>
      </div>
    </ApprovalDialog>
  );
}
