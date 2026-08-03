# Spec 14 — Server Groups & Fleet Views

**Status:** 📋 · **Depends on:** 01, 03 · **Spec owner:** frontend (grouping), core (group store)

## 1. Overview

Folders and tags turn a flat server list into an organized fleet, with a
group-level status rollup and a monitoring grid across the whole group —
"all prod boxes on one screen."

## 2. Goals / non-goals

**Goals**
- Groups: named folders for servers (nested one level), plus free-form tags.
- Sidebar: groups collapsible, group headers show connected/error counts.
- Group view: status rollup + mini monitoring grid (CPU/mem/disk per server).
- Group-scoped actions: open all, run script (broadcast preselected), scan logs across the group.

**Non-goals**
- No hierarchical grouping beyond one level, no team-shared groups, no auto-grouping rules (v1).

## 3. User stories

- I put 14 client servers in `clients/acme` and see at a glance that 2 are erroring.
- I open the group view and see every box's gauges in one grid.
- I run a cleanup script across the group with broadcast preselected (spec 06).

## 4. UI/UX

### 4.1 Sidebar
- Group headers (name + counts: `● 12` connected / `● 2` error), collapsible, servers indented under them; ungrouped section "Ungrouped".
- Drag a server onto a group header to move it; group context menu (rename, delete — servers move to Ungrouped, never deleted).
- Filter `/` also matches group names.

### 4.2 Group view (click a group header)
- Header: group name · server count · aggregate status (any error → red).
- Grid of server cards: status dot, name, host, mini sparklines (CPU/mem/disk from spec 03 caches, 60 samples).
- Card click → open server tab; group toolbar: "Run script…" (opens broadcast with the group preselected), "Scan logs" (per-server log scan summaries), "Refresh".

### 4.3 Tags
- Server modal gets a tags input (comma-separated); tag chips in the sidebar footer filter the list (click chip → filter).

## 5. Bridge API

### `oars.groups.list` → `{ok, groups:[{id, name, server_ids:[]}]}`
### `oars.groups.save` `{group}` → `{ok}` (create/rename/move membership — membership stored as server_ids array; Server.group field kept as the source of truth in v1, groups derived from it; choose one: **v1 = derive from Server.group string**, so groups.list is client-side. Bridge only needed when groups get metadata — defer.)
- **Decision (v1):** `Server.group` (single string, already in the model) is the source of truth. `oars.groups.*` is deferred until groups need descriptions/order; the frontend derives group headers + counts from `servers.list`. Tags live client-side in localStorage (v1), promoted to the model if they prove useful.
### Group-scoped actions reuse existing commands (broadcast `server_ids[]` from the group membership; monitor poll per server).

## 6. Zig core design

- Only the existing `group` field on `Server` (spec 01). No new module in v1.

## 7. Data model

- `servers.json` gains `group` values; no new files. Tags in localStorage until promoted.

## 8. Security

- Grouping is presentational; no permissions model (all local, single user).

## 9. Performance

- Group view polls monitor snapshots for visible cards only (≤ 12 visible), 5 s refresh (heavier than 2 s single-server).

## 10. Edge cases

- Group deleted with servers in it → servers become Ungrouped (never deleted).
- Server with group string but group filtered away → treated as Ungrouped; group resurrected on next list (derived — no orphan state).
- Same server in two "groups" via tags → groups are folders (exclusive), tags are inclusive; UI makes the distinction in tooltips.

## 11. Testing

- Manual: drag-move, collapsible state persistence (localStorage), group view grid, broadcast preselection.
- Unit: derived grouping logic (client-side) — group counts, ungrouped fallback.

## 12. Acceptance criteria

- [ ] Group assignment persists and survives restart (via Server.group).
- [ ] Group header shows live connected/error counts.
- [ ] Group view renders monitor grid at ≤ 5 s staleness.
- [ ] Deleting a group never deletes servers.

## 13. Research & References

- **Data model decision** — v1 derives groups from `Server.group` (a
  single string field, already in the model — `src/servers.zig` L27,
  see spec 01 §13). This is a deliberate product decision: no new
  store until groups need metadata (order, description). The bridge
  surface stays zero: `servers.list` already returns `group`.
- **Monitor grid staleness** — reuses the spec 03 snapshot cache
  (`MonitorCache`, probe-on-demand with refresh-if-stale, §6) so a
  group view polls the same cached snapshots; 5 s refresh is a UI
  cadence, not a probe cadence (idle cost bounded per spec 03 §9).
- **Folder-vs-tag semantics** — folders are exclusive, tags inclusive:
  a common UX convention in fleet tools; no external standard to cite
  (product decision recorded here so the UI copy stays consistent).
- **Drag-and-drop persistence** — client-side only until the group
  store exists; moving a server between groups writes
  `oars.servers.save` (spec 01 §5) with the new `group` value.

Sources: `src/servers.zig`, spec 01 §13, spec 03 §13.
