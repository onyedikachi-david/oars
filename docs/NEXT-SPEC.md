# Next Spec Implementation Guide

## Target

Implement the frontend for [spec 04, Log Management](specs/04-logs.md).
The backend is present and tested. The current `LogsTab` is an early draft,
not a complete product surface. Keep the target contract in the spec. Do not
reduce it to match the draft.

Read these files before editing:

- `docs/DESIGN.md`
- `docs/specs/04-logs.md`
- `docs/specs/02-terminal.md`, for cursor streams and channel cleanup
- `docs/specs/05-file-manager.md`, for downloads and transfer progress
- `frontend/src/LogsTab.tsx`
- `frontend/src/MonitorTab.tsx`, for current Oars dialogs, async channel reads,
  notices, responsive lists, and loading states
- `frontend/src/bridge.ts` and `frontend/src/types.ts`
- `src/bridge.zig`, starting at the spec 04 log handlers
- `src/logs.zig`

## Current Checkout Truth

The backend provides these commands:

- `oars.logs.scan`
- `oars.logs.read`
- `oars.logs.follow`
- `oars.logs.clear`
- `oars.logs.addSource`
- `oars.ssh.poll` and `oars.ssh.closeChannel`
- `oars.sftp.download`, `oars.sftp.poll`, and `oars.sftp.cancel`

`native-sdk.dialog.saveFile` is also allowlisted in `src/main.zig`. Use it to
choose the local download target. Do not send a whole log through a JSON bridge
response. Use the existing SFTP transfer operation and show its real progress.

The current frontend has important gaps:

- `LogsTab` uses one `search` value for source filtering and line search.
  These are separate tasks and need separate state and controls.
- `scan` depends on `selected`, while the scan effect depends on `scan`. A
  selection change can cause another scan. Remove that dependency cycle.
- Follow does not exist. The finished view must own one channel, one absolute
  cursor, and a visible dropped-byte warning.
- Source changes, Follow off, tab unmount, and server changes must call
  `oars.ssh.closeChannel` for the owned follow channel.
- The clear client omits the required identity preview. The backend requires
  `expected: {size, mtime, mode}` from the selected `LogSource` and returns
  `before_size` and `after_size`.
- Partial scans, limited reads, unreadable sources, stale-clear conflicts,
  missing files, channel EOF, and transfer failures do not have complete UI.
- Download is absent from `api.logs`. Add typed native-dialog and SFTP helpers;
  do not invent an `oars.logs.download` implementation that bypasses SFTP.
- The current markup uses generic inputs and buttons and has no matching Oars
  layout in `index.css`.

## Implementation Order

1. **Correct the bridge contract.** Add strict result types for scan, clear,
   SFTP transfer snapshots, and the native save dialog. Change `logs.clear`
   so it accepts the exact selected source preview. Add typed SFTP download,
   poll, and cancel methods.

2. **Build explicit state machines.** Keep scan, read, follow, clear, add, and
   download status separate. Use request generations or cancellation flags so
   an old read cannot replace a newer selection. Do not overlap follow polls.

3. **Implement follow ownership.** Start `oars.logs.follow`, poll only its
   channel with an absolute cursor, append bounded output, and surface
   `dropped`. Treat EOF as a stopped or disappeared source. Close the channel
   on every exit path. Do not claim that channel close proves remote-process
   termination beyond the backend contract.

4. **Build the Oars layout.** Use one focused split workspace: a restrained
   source rail and a large log viewer. Do not nest cards. Use Geist Sans for
   controls and source metadata. The log body is the one approved full-body
   Geist Mono surface. On mobile, use a compact source selector or sheet above
   the viewer instead of squeezing two panes.

5. **Separate search tasks.** Source search filters names and paths. Viewer
   search highlights safe text segments in the loaded lines and reports the
   match count. Do not use `dangerouslySetInnerHTML`. Keep 5,000-line rendering
   responsive; use a proven virtualizer if measured browser behavior needs it.

6. **Make destructive work deliberate.** Clear uses an Oars modal with a
   title, one-sentence effect, affected server and path, current size and
   modification time, permanent-warning copy, Cancel, and Clear. Pass the
   selected source preview unchanged. On a stale-preview conflict, rescan and
   require a new confirmation. Never retry clear automatically.

7. **Finish download through SFTP.** Ask for a destination with the native
   save dialog. Start `oars.sftp.download`, poll the returned operation, show
   bytes and status, allow cancel while active, and report the final local
   destination. Do not create local paths in frontend code.

8. **Handle every honest state.** Cover first scan, scanning skeleton, empty
   scan, partial scan reason, unreadable source, read limit, no matches,
   waiting-for-follow data, live, paused, dropped bytes, missing source,
   clear conflict, and download failure. Keep old readable content visible
   during refresh when it is still valid.

## Preview Harness

Extend `frontend/preview.html`; do not replace or delete it. Add deterministic
log fixtures for:

- grouped web, runtime, system, and custom sources
- a recent large source, an unreadable source, and a partial scan
- 200 to 5,000 lines with repeatable search matches and one very long line
- a limited read response
- follow chunks, a rotation-style continuation, dropped bytes, and EOF
- stale clear rejection followed by a successful fresh clear
- SFTP download progress, completion, failure, and cancel

Keep existing fleet, terminal, and monitor fixtures working. Record mock calls
so browser checks can prove exact payloads, cursors, channel close, and clear
identity data.

## Validation Gate

Do not mark spec 04 implemented until all of these checks pass:

- `npm --prefix frontend run build`
- `git diff --check`
- `zig build test` with the repository cache arguments when needed
- Desktop browser checks at 1440 x 1000 in light and dark themes
- Mobile browser checks at 390 x 844
- Scan grouping, source search, source selection, line-count changes, viewer
  search and highlights, and partial/unreadable/limited states
- Follow start, chunk append, auto-scroll, user scroll hold, dropped warning,
  stop, source switch, and unmount channel cleanup
- Clear approval payload, stale conflict, rescan, successful clear, and result
- Download save dialog, progress, cancel, completion, and failure
- No layout overflow, text overlap, console errors, or stale async updates

After validation, update `docs/specs/04-logs.md`, `docs/specs/README.md`, and
`docs/HANDOVER.md` with only the behaviors that the current checkout proves.
Leave PM2-specific enhancements and spec 05 file-manager work scoped to their
own contracts unless they are required for the log download path.
