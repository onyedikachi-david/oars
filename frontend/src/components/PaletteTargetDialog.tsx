import { useId, useState } from "react";
import { Server as ServerIcon } from "lucide-react";
import type { Server } from "../types";
import { ApprovalDialog } from "../features/files/dialogs/ApprovalDialog";
import { Button } from "./ui/button";
export function PaletteTargetDialog({ title, servers, onSelect, onClose }: { title: string; servers: Server[]; onSelect: (server: Server) => void; onClose: () => void }) {
  const id = useId(); const [query, setQuery] = useState(""); const visible = servers.filter(server => `${server.name} ${server.host} ${server.group}`.toLowerCase().includes(query.toLowerCase()));
  return <ApprovalDialog icon={<ServerIcon />} iconClass="" title={title} labelledBy={`${id}-title`} subtitle="Choose the server. This opens the feature for review." onCancel={onClose} actions={<Button variant="ghost" onClick={onClose}>Cancel</Button>}>
    <label htmlFor={`${id}-search`}>Filter servers</label><input id={`${id}-search`} className="oars-data-input" value={query} onChange={event => setQuery(event.target.value)} />
    <div style={{ maxHeight: 320, overflow: "auto", display: "grid", gap: 6 }}>{visible.map(server => <Button key={server.id} variant="outline" onClick={() => onSelect(server)}>{server.name} · {server.host}</Button>)}</div>
    {!visible.length && <p>No matching servers. Add a connection profile first.</p>}
  </ApprovalDialog>;
}
