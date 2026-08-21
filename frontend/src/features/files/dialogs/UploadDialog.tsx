import { Upload } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { rpFromUtf8, type RemotePath } from "../../../sftp-path";
import { FileIcon } from "../components/FileIcon";
import { MonoPath } from "../components/MonoPath";
import { fmtBytes } from "../formatters";
import type { UploadIntent } from "../types";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface UploadDialogProps {
  intents: UploadIntent[];
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: () => Promise<void>;
}

export function UploadDialog({ intents, parent, onCancel, onConfirm }: UploadDialogProps) {
  const totalBytes = intents.reduce((n, i) => n + i.file.size, 0);
  const { busy, error, run } = useDialogAction();
  const submit = async () => {
    if (busy) return;
    await run(onConfirm);
  };

  return (
    <ApprovalDialog
      icon={<Upload />}
      iconClass=""
      title={`Upload ${intents.length} ${intents.length === 1 ? "file" : "files"}?`}
      subtitle={
        <>
          to <MonoPath rp={parent} />
        </>
      }
      labelledBy="fs-upload-title"
      busy={busy}
      onCancel={onCancel}
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy}>
            Start upload
          </Button>
        </>
      }
    >
      <p className="muted" style={{ margin: 0 }}>
        {intents.length} {intents.length === 1 ? "file" : "files"} · {fmtBytes(totalBytes)} total.
        {intents.some((i) => i.relativePath) ? " Folder structure is preserved." : ""}
      </p>
      <ul className="fs-upload-list">
        {intents.slice(0, 6).map((i, idx) => (
          <li key={idx}>
            <FileIcon
              entry={{
                name: rpFromUtf8(i.file.name),
                display: i.file.name,
                kind: "file",
                size: i.file.size,
                mtime: 0,
                mode: "",
                uid: 0,
                gid: 0,
                link_target: null,
              }}
              size={13}
            />{" "}
            {i.file.name} <span className="muted">· {fmtBytes(i.file.size)}</span>
          </li>
        ))}
        {intents.length > 6 && <li className="muted">…and {intents.length - 6} more</li>}
      </ul>
      <p className="muted" style={{ margin: 0 }}>
        An existing file with the same name is never overwritten — the upload fails instead.
      </p>
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
