# Spec 14 — Server Groups & Fleet Views

**Status:** 📋 · **Depends on:** 01, 03 · **Spec owner:** frontend (grouping), core (server store)

## 1. Overview

Folders and tags turn a flat server list into an organized fleet, with a
group-level status rollup and a monitoring grid across the whole group —
"all prod boxes on one screen."

## 2. Goals / non-goals

**Goals**
- Groups: named folders nested one level, plus free-form tags. A server has one
  folder path and any number of tags.
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
- The server modal has a tags input with normalized, deduplicated values. Tag
  chips in the sidebar filter the server list. Tags persist in the canonical
  `Server.tags` field, so export/import and every app window see the same data.

## 5. Bridge API

No new bridge API in v1. `Server.group` and `Server.tags` are the source of
truth, and the frontend derives group headers, counts, and tag filters from
`servers.list`. A one-level nested group is stored as `parent/child`; each
segment cannot contain `/`, and the full value can contain at most one `/`.
Rename or delete updates every matching server
profile through `oars.servers.save` and reports partial failures. Add
`oars.groups.*` only when groups gain independent metadata.
### Group-scoped actions reuse existing commands (broadcast `server_ids[]` from the group membership; monitor poll per server).

## 6. Zig core design

- The existing Server store gains `tags: []const []const u8` beside `group`.
  Validation trims tags, rejects empty or control-character values, compares
  tags case-insensitively for deduplication, and preserves the user's casing.
  No new module is needed in v1.

## 7. Data model

- `servers.json` stores `group` and `tags`; no new files.

## 8. Security

- Grouping is presentational; no permissions model (all local, single user).

## 9. Performance

- Group view polls monitor snapshots for visible cards only (≤ 12 visible), 5 s refresh (heavier than 2 s single-server).

## 10. Edge cases

- Group deleted with servers in it → servers become Ungrouped (never deleted).
- A saved non-empty group path always produces its group header. There is no
  independent group record that can become orphaned, and an empty group does
  not persist in v1.
- A server has one exclusive group path and any number of inclusive tags. The
  UI names these concepts directly and never presents a tag as a folder.

## 11. Testing

- Manual: drag-move, collapsible state persistence, tag editing/filtering,
  group view grid, and broadcast preselection.
- Unit: derived grouping logic, one-level path validation, tag normalization and
  deduplication, group counts, and ungrouped fallback.

## 12. Acceptance criteria

- [ ] Group assignment persists and survives restart (via Server.group).
- [ ] Tags persist in `Server.tags`, survive restart and export/import, and
      filter the sidebar without becoming a second source of truth.
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
- **Tags persistence correction** — the earlier localStorage plan created a
  second source of truth that export/import could not carry. The planned tags
  feature remains, but `Server.tags` is now canonical.
- **Drag-and-drop persistence** — client-side only until the group
  store exists; moving a server between groups writes
  `oars.servers.save` (spec 01 §5) with the new `group` value.

Sources: `src/servers.zig`, spec 01 §13, spec 03 §13.
