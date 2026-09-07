import { useId, useState } from "react";
import { X } from "lucide-react";
import { useModalFocus } from "./useModalFocus";
import { ApplicationOverlay } from "./ApplicationPortal";
import { Button } from "./ui/button";
import { VaultTab } from "../VaultTab";
export function DataSettings({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const id = useId(); const [busy, setBusy] = useState(false); const ref = useModalFocus(onClose, undefined, !busy);
  return <ApplicationOverlay quiet><div ref={ref} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} className="oars-modal transfer-dialog">
    <header className="preferences-header"><h2 id={`${id}-title`}>Data transfer</h2><Button variant="ghost" size="icon-sm" disabled={busy} aria-label="Close data settings" onClick={onClose}><X /></Button></header>
    <VaultTab onImported={onImported} onBusyChange={setBusy} />
  </div></ApplicationOverlay>;
}
