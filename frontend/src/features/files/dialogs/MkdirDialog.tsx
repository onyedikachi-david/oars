import { useState } from "react";
import { FolderPlus } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { rpFromUtf8, rpJoin, validateLeafName, type RemotePath } from "../../../sftp-path";
import { MonoPath } from "../components/MonoPath";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface MkdirDialogProps {
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: (name: string) => Promise<void>;
}

export function MkdirDialog({ parent, onCancel, onConfirm }: MkdirDialogProps) {
  const [name, setName] = useState("");
  const { busy, error, run } = useDialogAction();
  const nameError = validateLeafName(name.trim());
  const submit = async () => {
    if (nameError || busy) return;
    await run(() => onConfirm(name.trim()));
  };

  return (
    <ApprovalDialog
      icon={<FolderPlus />}
      iconClass=""
      title="New folder"
      subtitle={
        <>
          in <MonoPath rp={parent} />
        </>
      }
      labelledBy="fs-mkdir-title"
      busy={busy}
      onCancel={onCancel}
      initialFocusSelector="input.fs-input"
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={Boolean(nameError) || busy}>
            Create folder
          </Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Create one folder inside the current remote location.</p>
      <div className="fs-dialog-target">
        <span>Will create</span>
        <MonoPath rp={name.trim() && !nameError ? rpJoin(parent, rpFromUtf8(name.trim())) : parent} />
      </div>
      <label className="fs-field">
        <span>Folder name</span>
        <input
          className="fs-input"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
          }}
          placeholder="e.g. backups"
        />
      </label>
      {name.trim() && nameError && <div className="oars-form-error">{nameError}</div>}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
