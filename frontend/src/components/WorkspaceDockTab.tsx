import { createContext, useContext } from "react";
import { GripVertical } from "lucide-react";
import type { TabButtonRenderer } from "react-mosaic-component";
import { useWorkspaceDocking } from "./WorkspaceDocking";

export const WorkspaceDockTabContext = createContext<{
  names: Record<string, string>;
  onSelect: (key: string) => void;
}>({ names: {}, onSelect: () => {} });

// Mosaic renders this callback as a component. Keep its identity stable so
// polling and drag updates cannot replace a focused button or drag source.
export function WorkspaceDockTab(props: Parameters<TabButtonRenderer<string>>[0]) {
  const { names, onSelect } = useContext(WorkspaceDockTabContext);
  const begin = useWorkspaceDocking();
  return <button type="button" className={`workspace-dock-tab ${props.isActive ? "is-active" : ""}`}
    aria-pressed={props.isActive} draggable={false} data-workspace-tab={props.tabKey}
    onPointerDown={(event) => { onSelect(props.tabKey); begin(event, props.tabKey); }}
    onClick={() => { props.onTabClick(); onSelect(props.tabKey); }}>
    <GripVertical aria-hidden />{names[props.tabKey] ?? props.tabKey}
  </button>;
}
