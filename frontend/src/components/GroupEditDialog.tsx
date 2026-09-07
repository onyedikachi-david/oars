import { useId, useState } from "react";
import { Folder } from "lucide-react";
import type { Server } from "../types";
import { moveGroupProfiles } from "../fleet";
import { ApprovalDialog } from "../features/files/dialogs/ApprovalDialog";
import { Button } from "./ui/button";
export function GroupEditDialog({ servers, group, remove = false, onUpdated, onClose }: { servers: Server[]; group: string; remove?: boolean; onUpdated: (servers: Server[]) => void; onClose: () => void }) {
  const id = useId(); const [name, setName] = useState(group); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [remaining, setRemaining] = useState(servers);
  const close = () => { if (!busy) onClose(); };
  return <ApprovalDialog icon={<Folder />} iconClass="" title={remove ? `Delete group “${group}”?` : servers.length === 1 ? "Move server to group" : "Rename group"} labelledBy={`${id}-title`} subtitle={remove ? "Servers will move to Ungrouped. No server profiles or connections are deleted." : "Use a group name or one parent/child path. Leave empty for Ungrouped."} onCancel={close} busy={busy} actions={<><Button variant="ghost" disabled={busy} onClick={close}>Cancel</Button><Button disabled={busy} onClick={async () => {
    setBusy(true); setError("");
    try {
      const result = await moveGroupProfiles(remaining, remove ? "" : name);
      onUpdated(result.updated);
      if (!result.failures.length) onClose();
      else { setRemaining(remaining.filter(server => result.failures.some(failure => failure.id === server.id))); setError(`${result.updated.length} updated. Retry failed profiles: ${result.failures.map(failure => `${failure.name}: ${failure.message}`).join("; ")}`); }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }}>{busy ? "Saving…" : remove ? "Move servers to Ungrouped" : "Save group"}</Button></>}>
    {!remove && <><label htmlFor={`${id}-name`}>Group path</label><input id={`${id}-name`} className="oars-data-input" value={name} disabled={busy} onChange={event => setName(event.target.value)} /></>}
    <details className="group-affected"><summary>{remaining.length} {remaining.length === 1 ? "profile" : "profiles"} affected</summary><ul>{remaining.map(server => <li key={server.id}>{server.name}<span>{server.host}</span></li>)}</ul></details>{error && <p role="alert">{error}</p>}
  </ApprovalDialog>;
}
