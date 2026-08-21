import { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { entryKey, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { FileIcon } from "../components/FileIcon";
import { MonoPath } from "../components/MonoPath";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface DeleteDialogProps {
  entries: SftpEntry[];
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: (recursive: boolean) => Promise<void>;
}

export function DeleteDialog({ entries, parent, onCancel, onConfirm }: DeleteDialogProps) {
  const [confirmText, setConfirmText] = useState("");
  const { busy, error, run } = useDialogAction();
  const hasDir = entries.some((e) => e.kind === "dir");
  const recursive = hasDir || entries.length > 1;
  const single = entries.length === 1 ? entries[0] : null;
  const confirmName = single ? single.display : `${entries.length} items`;
  const needsTyping = hasDir;
  const ready = !needsTyping || confirmText === confirmName;

  const submit = async () => {
    if (!ready || busy) return;
    await run(() => onConfirm(recursive));
  };

  return (
    <ApprovalDialog
      icon={<Trash2 />}
      iconClass="oars-modal-icon-danger"
      title={
        needsTyping
          ? "Permanently delete this folder?"
          : `Delete ${entries.length > 1 ? `${entries.length} items` : "this item"}?`
      }
      subtitle={
        <>
          from <MonoPath rp={parent} />
        </>
      }
      labelledBy="fs-delete-title"
      busy={busy}
      onCancel={onCancel}
      initialFocusSelector={needsTyping ? "input.fs-input" : "[data-delete-confirm]"}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            data-delete-confirm
            variant="destructive"
            onClick={() => void submit()}
            disabled={!ready || busy}
          >
            Delete {recursive ? "recursively" : ""}
          </Button>
        </>
      }
    >
      <ul className="fs-delete-list">
        {entries.slice(0, 8).map((e) => (
          <li key={entryKey(e)}>
            <FileIcon entry={e} size={13} /> {e.display}
            {e.kind === "dir" ? "/" : ""}
          </li>
        ))}
        {entries.length > 8 && <li className="muted">…and {entries.length - 8} more</li>}
      </ul>
      {needsTyping ? (
        <label className="fs-field">
          <span>
            Type <strong>{confirmName}</strong> to confirm — this cannot be undone.
          </span>
          <input
            className="fs-input"
            autoFocus
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void submit();
            }}
          />
        </label>
      ) : (
        <p className="muted" style={{ margin: 0 }}>
          This cannot be undone. {hasDir ? "Folder contents are removed recursively." : ""}
        </p>
      )}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
