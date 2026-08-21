import { FileArchive } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { rpJoin, rpParent, rpStem, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { MonoPath } from "../components/MonoPath";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface UnzipDialogProps {
  entry: SftpEntry;
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: () => Promise<void>;
}

export function UnzipDialog({ entry, parent, onCancel, onConfirm }: UnzipDialogProps) {
  const { busy, error, run } = useDialogAction();
  const zipPath = rpJoin(parent, entry.name);
  const dest = rpJoin(rpParent(zipPath), rpStem(zipPath));
  const submit = async () => {
    if (busy) return;
    await run(onConfirm);
  };

  return (
    <ApprovalDialog
      icon={<FileArchive />}
      iconClass=""
      title="Expand ZIP archive"
      subtitle={
        <>
          from <MonoPath rp={zipPath} />
        </>
      }
      labelledBy="fs-unzip-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy}>
            Expand here
          </Button>
        </>
      }
    >
      <div className="fs-unzip-preview">
        <p className="muted" style={{ margin: 0 }}>
          The archive contents are extracted into a new folder next to the archive:
        </p>
        <MonoPath rp={dest} />
        <p className="muted" style={{ margin: 0 }}>
          Nothing is overwritten — the extraction refuses existing paths, and the archive is validated before anything
          is written.
        </p>
      </div>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
