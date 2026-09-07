import { Menu } from "@base-ui/react/menu";
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, ChevronRight, Copy, Layers, MoreHorizontal, Pencil, X } from "lucide-react";
import { Button } from "./ui/button";
import type { WorkspaceDockPosition } from "../workspace-layout";

const destinations = [
  { id: "left", label: "Move to left", icon: ArrowLeft },
  { id: "right", label: "Move to right", icon: ArrowRight },
  { id: "top", label: "Move above", icon: ArrowUp },
  { id: "bottom", label: "Move below", icon: ArrowDown },
  { id: "tab", label: "Group as tabs", icon: Layers },
] as const;

export function WorkspacePaneMenu({ name, peers, canDuplicate, onDock, onDuplicate, onEdit, onClose }: {
  name: string;
  peers: { key: string; label: string }[];
  canDuplicate: boolean;
  onDock: (target: string, position: WorkspaceDockPosition) => void;
  onDuplicate: () => void;
  onEdit: () => void;
  onClose: () => void;
}) {
  return <Menu.Root>
    <Menu.Trigger render={<Button variant="ghost" size="icon-sm" />} aria-label={`Arrange ${name}`} title="Arrange pane">
      <MoreHorizontal />
    </Menu.Trigger>
    <Menu.Portal>
      <Menu.Positioner className="workspace-pane-menu-positioner" sideOffset={6} align="end">
        <Menu.Popup className="workspace-pane-menu">
          <Menu.Group>
            <Menu.GroupLabel className="workspace-pane-menu-label">{name}</Menu.GroupLabel>
            <Menu.Item onClick={onDuplicate} disabled={!canDuplicate}><Copy /><span>Open another view</span></Menu.Item>
            <Menu.Item onClick={onEdit}><Pencil /><span>Edit profile</span></Menu.Item>
          </Menu.Group>
          {peers.length > 0 && <Menu.Group>
            <Menu.GroupLabel className="workspace-pane-menu-label">Move beside</Menu.GroupLabel>
            {peers.map((peer) => <Menu.SubmenuRoot key={peer.key}>
              <Menu.SubmenuTrigger><Layers /><span>{peer.label}</span><ChevronRight /></Menu.SubmenuTrigger>
              <Menu.Portal><Menu.Positioner className="workspace-pane-menu-positioner" sideOffset={6}>
                <Menu.Popup className="workspace-pane-menu" aria-label={`Move beside ${peer.label}`}>
                  {destinations.map(({ id, label, icon: Icon }) => <Menu.Item key={id} onClick={() => onDock(peer.key, id)}>
                    <Icon /><span>{label}</span>
                  </Menu.Item>)}
                </Menu.Popup>
              </Menu.Positioner></Menu.Portal>
            </Menu.SubmenuRoot>)}
          </Menu.Group>}
          <Menu.Group><Menu.Item onClick={onClose}><X /><span>Close pane</span></Menu.Item></Menu.Group>
        </Menu.Popup>
      </Menu.Positioner>
    </Menu.Portal>
  </Menu.Root>;
}
