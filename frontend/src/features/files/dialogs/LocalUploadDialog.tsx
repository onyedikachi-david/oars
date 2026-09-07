import { ArrowRight, FileText } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { LocalEntry, RemotePath } from "../../../types";
import { MonoPath } from "../components/MonoPath";
import { fmtBytes } from "../formatters";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface LocalUploadDialogProps {
  entries: LocalEntry[];
  remoteParent: RemotePath;
  onCancel: () => void;
  onConfirm: () => Promise<void>;
}

export function LocalUploadDialog({ entries, remoteParent, onCancel, onConfirm }: LocalUploadDialogProps) {
  const totalBytes = entries.reduce((total, entry) => total + entry.size, 0);
  const { busy, error, run } = useDialogAction();

  return (
    <ApprovalDialog
      icon={<ArrowRight />}
      iconClass=""
      title={`Upload ${entries.length} local ${entries.length === 1 ? "file" : "files"}?`}
      subtitle={
        <>
          to <MonoPath rp={remoteParent} />
        </>
      }
      labelledBy="fs-local-upload-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void run(onConfirm)} disabled={busy}>
            Upload to remote
          </Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Copy these files from the approved local folder into the current remote folder.</p>
      <div className="fs-dialog-target">
        <span>Destination</span>
        <MonoPath rp={remoteParent} />
        <span>Total</span>
        <strong>{fmtBytes(totalBytes)}</strong>
      </div>
      <ul className="fs-upload-list">
        {entries.slice(0, 8).map((entry) => (
          <li key={entry.path}>
            <FileText size={13} /> {entry.name} <span className="muted">· {fmtBytes(entry.size)}</span>
          </li>
        ))}
        {entries.length > 8 && <li className="muted">…and {entries.length - 8} more</li>}
      </ul>
      <p className="muted" style={{ margin: 0 }}>
        Existing remote targets are never overwritten.
      </p>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
