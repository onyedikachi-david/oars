import { useEffect, useRef, type PointerEvent as ReactPointerEvent } from "react";
import type { Server } from "./types";
export function useFleetMove(onMove: (server: Server, group: string) => void) {
  const drag = useRef<{ server: Server; x: number; y: number; moved: boolean; pointer: number } | null>(null);
  const suppressClick = useRef(false);
  useEffect(() => {
    const cancel = (event: KeyboardEvent) => { if (event.key === "Escape" && drag.current) { drag.current = null; suppressClick.current = true; } };
    window.addEventListener("keydown", cancel, true); return () => window.removeEventListener("keydown", cancel, true);
  }, []);
  return {
    onPointerDown: (event: ReactPointerEvent<HTMLElement>, server: Server) => {
      if (event.button !== 0) return;
      suppressClick.current = false; drag.current = { server, x: event.clientX, y: event.clientY, moved: false, pointer: event.pointerId };
      event.currentTarget.setPointerCapture?.(event.pointerId);
    },
    onPointerMove: (event: ReactPointerEvent<HTMLElement>) => {
      const current = drag.current; if (!current || event.pointerId !== current.pointer) return;
      if (Math.hypot(event.clientX - current.x, event.clientY - current.y) > 6) current.moved = true;
      if (current.moved) {
        event.preventDefault();
        const list = event.currentTarget.closest<HTMLElement>(".sidebar-fleet-list");
        if (list) { const rect = list.getBoundingClientRect(); if (event.clientY < rect.top + 24) list.scrollTop -= 12; else if (event.clientY > rect.bottom - 24) list.scrollTop += 12; }
      }
    },
    onPointerUp: (event: ReactPointerEvent<HTMLElement>) => {
      const current = drag.current; drag.current = null;
      if (!current?.moved) return;
      suppressClick.current = true;
      const target = document.elementFromPoint(event.clientX, event.clientY)?.closest<HTMLElement>("[data-fleet-group-drop]");
      if (target) { const group = target.dataset.fleetGroupDrop ?? ""; if (group !== current.server.group) onMove(current.server, group); }
    },
    onPointerCancel: () => { drag.current = null; suppressClick.current = true; },
    onLostPointerCapture: () => { drag.current = null; },
    consumeClick: () => { const suppress = suppressClick.current; suppressClick.current = false; return suppress; },
  };
}
