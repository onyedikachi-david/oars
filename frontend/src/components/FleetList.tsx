import { Fragment, useEffect, useMemo, useRef, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Server } from "../types";
export interface FleetGroup { key: string; path: string; label: string; entries: Server[]; }
type Row = { key: string; group: FleetGroup; server?: Server };
export function FleetList({ groups, collapsed, expandAll, activeServerId, renderGroup, renderServer, empty }: { groups: FleetGroup[]; collapsed: ReadonlySet<string>; expandAll: boolean; activeServerId?: string; renderGroup: (group: FleetGroup) => ReactNode; renderServer: (server: Server) => ReactNode; empty: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const rows = useMemo<Row[]>(() => groups.flatMap(group => [{ key: `group:${group.key}`, group }, ...(!expandAll && collapsed.has(group.key) ? [] : group.entries.map(server => ({ key: `server:${server.id}`, group, server })))] satisfies Row[]), [groups, collapsed, expandAll]);
  const virtual = rows.length > 200;
  const virtualizer = useVirtualizer({ count: rows.length, enabled: virtual, getScrollElement: () => ref.current, getItemKey: index => rows[index].key, estimateSize: index => rows[index].server ? rows[index].server!.tags.length ? 68 : 44 : 44, overscan: 8, initialRect: { width: 220, height: 400 }, useFlushSync: false });
  useEffect(() => {
    if (!virtual || !activeServerId) return;
    const index = rows.findIndex(row => row.server?.id === activeServerId);
    if (index >= 0) virtualizer.scrollToIndex(index, { align: "auto" });
  }, [activeServerId, virtual]);
  const render = (row: Row) => row.server ? renderServer(row.server) : renderGroup(row.group);
  return <div ref={ref} className="sidebar-fleet-list" role="list" aria-label="Server profiles">
    {!rows.length ? <div className="sidebar-fleet-empty">{empty}</div> : virtual ? <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
      {virtualizer.getVirtualItems().map(item => <div key={item.key} data-index={item.index} ref={virtualizer.measureElement} style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${item.start}px)` }}>{render(rows[item.index])}</div>)}
    </div> : rows.map(row => <Fragment key={row.key}>{render(row)}</Fragment>)}
  </div>;
}
