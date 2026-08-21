import { useState } from "react";
import { Pencil } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { rpFromUtf8, rpJoin, validateLeafName, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { MonoPath } from "../components/MonoPath";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface RenameDialogProps {
  entry: SftpEntry;
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: (name: string) => Promise<void>;
}

export function RenameDialog({ entry, parent, onCancel, onConfirm }: RenameDialogProps) {
  const [name, setName] = useState(entry.display);
  const { busy, error, run } = useDialogAction();
  const nameError = validateLeafName(name.trim());
  const submit = async () => {
    if (nameError || busy || name === entry.display) return;
    await run(() => onConfirm(name.trim()));
  };

  return (
    <ApprovalDialog
      icon={<Pencil />}
      iconClass=""
      title="Rename"
      subtitle={
        <>
          in <MonoPath rp={parent} />
        </>
      }
      labelledBy="fs-rename-title"
      busy={busy}
      onCancel={onCancel}
      initialFocusSelector="input.fs-input"
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={Boolean(nameError) || name === entry.display || busy}>
            Rename
          </Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Change this item’s name without moving it out of the current folder.</p>
      <div className="fs-dialog-target">
        <span>Current item</span>
        <MonoPath rp={rpJoin(parent, entry.name)} />
        <span>New identity</span>
        <MonoPath rp={name.trim() && !nameError ? rpJoin(parent, rpFromUtf8(name.trim())) : parent} />
      </div>
      <label className="fs-field">
        <span>
          New name for <code className="fs-mono-path">{entry.display}</code>
        </span>
        <input
          className="fs-input"
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
          }}
        />
      </label>
      {name.trim() && nameError && <div className="oars-form-error">{nameError}</div>}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
