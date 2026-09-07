import { createContext, useContext, useLayoutEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

const SurfaceContext = createContext<Map<string, HTMLDivElement>>(new Map());

/** Stable portal targets preserve terminal output and editor state while a pane moves. */
export function WorkspaceSurfaces({ paneKeys, renderPane, children }: {
  paneKeys: string[];
  renderPane: (key: string) => ReactNode;
  children: ReactNode;
}) {
  const surfaces = useRef(new Map<string, HTMLDivElement>());
  for (const key of paneKeys) {
    if (!surfaces.current.has(key)) {
      const surface = document.createElement("div");
      surface.className = "workspace-pane-surface";
      surfaces.current.set(key, surface);
    }
  }
  useLayoutEffect(() => {
    for (const key of surfaces.current.keys()) if (!paneKeys.includes(key)) surfaces.current.delete(key);
  }, [paneKeys]);
  return <SurfaceContext.Provider value={surfaces.current}>
    {children}
    {paneKeys.map((key) => createPortal(renderPane(key), surfaces.current.get(key)!, key))}
  </SurfaceContext.Provider>;
}

export function WorkspacePaneSlot({ paneKey }: { paneKey: string }) {
  const surfaces = useContext(SurfaceContext);
  const slot = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const parent = slot.current;
    const surface = surfaces.get(paneKey);
    if (!parent || !surface) return;
    parent.appendChild(surface);
    return () => { if (surface.parentNode === parent) parent.removeChild(surface); };
  }, [paneKey, surfaces]);
  return <div ref={slot} className="workspace-pane-slot" />;
}
