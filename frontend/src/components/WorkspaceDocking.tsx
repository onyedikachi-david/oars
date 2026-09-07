import { createContext, useContext, useEffect, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { WorkspaceDockPosition } from "../workspace-layout";

type Destination = { key: string; position: WorkspaceDockPosition; rect: CSSProperties };
type Gesture = { key: string; pointerId: number; x: number; y: number; started: boolean; handle: HTMLElement };
const captions: Record<WorkspaceDockPosition, string> = { left: "Split left", right: "Split right", top: "Split above", bottom: "Split below", tab: "Group as tabs", "tab-before": "Insert tab before", "tab-after": "Insert tab after" };
const DockingContext = createContext<(event: ReactPointerEvent<HTMLElement>, key: string) => void>(() => {});
export const useWorkspaceDocking = () => useContext(DockingContext);

export function workspaceDropPosition(x: number, y: number, width: number, height: number): WorkspaceDockPosition {
  const edges = [{ position: "left", distance: x / width }, { position: "right", distance: 1 - x / width },
    { position: "top", distance: y / height }, { position: "bottom", distance: 1 - y / height }] as const;
  const nearest = [...edges].sort((a, b) => a.distance - b.distance)[0];
  return nearest.distance < 0.25 ? nearest.position : "tab";
}

/** Pointer capture avoids the native file-drop handler intercepting HTML drag/drop in WKWebView. */
export function WorkspaceDocking({ enabled, onDock, onStatus, children }: {
  enabled: boolean;
  onDock: (source: string, target: string, position: WorkspaceDockPosition) => void;
  onStatus: (message: string) => void;
  children: ReactNode;
}) {
  const root = useRef<HTMLDivElement>(null);
  const gesture = useRef<Gesture | null>(null);
  const suppressClick = useRef(false);
  const [preview, setPreview] = useState<Destination | null>(null);
  const [moving, setMoving] = useState(false);

  const clear = () => {
    const current = gesture.current;
    gesture.current = null;
    if (current?.handle.hasPointerCapture(current.pointerId)) current.handle.releasePointerCapture(current.pointerId);
    setPreview(null);
    setMoving(false);
  };
  const cancel = () => {
    if (gesture.current?.started) onStatus("Move cancelled. Layout unchanged.");
    clear();
  };
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && gesture.current) { event.preventDefault(); cancel(); }
    };
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("blur", cancel);
    return () => { window.removeEventListener("keydown", onKey, true); window.removeEventListener("blur", cancel); };
  });
  useEffect(() => { if (!enabled) cancel(); }, [enabled]);

  const destinationAt = (x: number, y: number): Destination | null => {
    const hit = document.elementFromPoint(x, y);
    const tab = hit?.closest<HTMLElement>("[data-workspace-tab]");
    if (tab && root.current?.contains(tab) && tab.dataset.workspaceTab !== gesture.current?.key) {
      const bounds = tab.getBoundingClientRect();
      return { key: tab.dataset.workspaceTab!, position: x < bounds.left + bounds.width / 2 ? "tab-before" : "tab-after",
        rect: { left: bounds.left, top: bounds.top, width: bounds.width, height: bounds.height } };
    }
    const pane = hit?.closest<HTMLElement>(".mosaic-window");
    if (!pane || !root.current?.contains(pane)) return null;
    let key = pane.querySelector<HTMLElement>("[data-workspace-pane]")?.dataset.workspacePane;
    if (!key) return null;
    const bounds = pane.getBoundingClientRect();
    if (bounds.width <= 0 || bounds.height <= 0) return null;
    const position = workspaceDropPosition(x - bounds.left, y - bounds.top, bounds.width, bounds.height);
    if (key === gesture.current?.key) {
      if (position === "tab") return null;
      // Pulling the active tab to an edge of its own group splits it out.
      key = Array.from(pane.closest(".mosaic-tabs-container")?.querySelectorAll<HTMLElement>("[data-workspace-tab]") ?? [])
        .map((tab) => tab.dataset.workspaceTab).find((candidate) => candidate !== gesture.current?.key);
      if (!key) return null;
    }
    let { left, top, width, height } = bounds;
    if (position === "left" || position === "right") { width /= 2; if (position === "right") left += width; }
    if (position === "top" || position === "bottom") { height /= 2; if (position === "bottom") top += height; }
    return { key, position, rect: { left: left + 4, top: top + 4, width: width - 8, height: height - 8 } };
  };
  const begin = (event: ReactPointerEvent<HTMLElement>, key: string) => {
    if (!enabled || event.button !== 0 || event.isPrimary === false || gesture.current) return;
    const handle = event.currentTarget;
    handle.setPointerCapture(event.pointerId);
    gesture.current = { key, pointerId: event.pointerId, x: event.clientX, y: event.clientY, started: false, handle };
  };
  const move = (event: ReactPointerEvent) => {
    const current = gesture.current;
    if (!current || event.pointerId !== current.pointerId) return;
    if (!current.started && Math.hypot(event.clientX - current.x, event.clientY - current.y) < 6) return;
    event.preventDefault();
    if (!current.started) { current.started = true; setMoving(true); onStatus("Drop at an edge to split, or in the center to group. Escape cancels."); }
    setPreview(destinationAt(event.clientX, event.clientY));
  };
  const finish = (event: ReactPointerEvent) => {
    const current = gesture.current;
    if (!current || event.pointerId !== current.pointerId) return;
    const target = current.started ? destinationAt(event.clientX, event.clientY) : null;
    suppressClick.current = current.started;
    clear();
    if (target) { onDock(current.key, target.key, target.position); onStatus("Pane moved."); }
    else if (current.started) onStatus("Move cancelled. Layout unchanged.");
  };
  return <DockingContext.Provider value={begin}>
    <div ref={root} className={`workspace-docking ${moving ? "is-docking" : ""}`}
      onPointerDownCapture={() => { suppressClick.current = false; }} onPointerMoveCapture={move} onPointerUpCapture={finish}
      onPointerCancel={cancel} onLostPointerCapture={() => { if (gesture.current) cancel(); }}
      onClickCapture={(event) => { if (suppressClick.current) { event.preventDefault(); event.stopPropagation(); } }}>
      {children}
    </div>
    {preview && createPortal(<div className="workspace-dock-preview" style={preview.rect} aria-hidden><span>{captions[preview.position]}</span></div>, document.body)}
  </DockingContext.Provider>;
}

export function WorkspaceDragHandle({ paneKey, children, onFocusPane }: { paneKey: string; children: ReactNode; onFocusPane: () => void }) {
  const begin = useWorkspaceDocking();
  return <div className="workspace-pane-drag" title="Drag to an edge to split, or to the center to group as tabs"
    onPointerDown={(event) => begin(event, paneKey)} onDoubleClick={onFocusPane} onDragStart={(event) => event.preventDefault()}>{children}</div>;
}
