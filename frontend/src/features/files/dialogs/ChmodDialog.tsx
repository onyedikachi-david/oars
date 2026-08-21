import { useState } from "react";
import { HardDrive } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { permissionStringToOctal } from "../../../file-state";
import { rpJoin, type RemotePath } from "../../../sftp-path";
import type { SftpEntry } from "../../../types";
import { MonoPath } from "../components/MonoPath";
import { modeString } from "../formatters";
import { ApprovalDialog } from "./ApprovalDialog";
import { useDialogAction } from "./useDialogAction";

export interface ChmodDialogProps {
  entry: SftpEntry;
  parent: RemotePath;
  onCancel: () => void;
  onConfirm: (mode: number) => Promise<void>;
}

export function ChmodDialog({ entry, parent, onCancel, onConfirm }: ChmodDialogProps) {
  const [mode, setMode] = useState(() => permissionStringToOctal(entry.mode));
  const { busy, error, run } = useDialogAction();
  const modeValue = parseInt(mode, 8);
  const valid = /^[0-7]{1,4}$/.test(mode) && modeValue >= 0 && modeValue <= 0o7777;
  const submit = async () => {
    if (!valid || busy) return;
    await run(() => onConfirm(modeValue));
  };

  return (
    <ApprovalDialog
      icon={<HardDrive />}
      iconClass=""
      title="Change permissions"
      subtitle={
        <>
          on <MonoPath rp={rpJoin(parent, entry.name)} />
        </>
      }
      labelledBy="fs-chmod-title"
      busy={busy}
      onCancel={onCancel}
      initialFocusSelector="input.fs-input"
      actions={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!valid || busy}>
            Apply permissions
          </Button>
        </>
      }
    >
      <p className="fs-dialog-explainer">Apply POSIX permission bits to this remote item.</p>
      <label className="fs-field">
        <span>Permission bits (octal)</span>
        <input
          className="fs-input fs-input-mono"
          autoFocus
          value={mode}
          onChange={(e) => setMode(e.target.value.replace(/[^0-7]/g, "").slice(0, 4))}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
          }}
          placeholder="644"
        />
      </label>
      {valid && (
        <p className="muted" style={{ margin: 0 }}>
          Will apply: {modeString(modeValue)}
        </p>
      )}
      {error && <div className="oars-form-error">{error}</div>}
    </ApprovalDialog>
  );
}
