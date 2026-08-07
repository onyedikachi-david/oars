# Next Spec Implementation Guide

## Target

Complete the frontend for [spec 05, File Manager](specs/05-file-manager.md).
The worker-owned SFTP backend and container integration path already exist.
The current `FilesTab` is a diagnostic browser. It does not implement the
product workflow, and some of its assumptions do not match the backend.

Read these files before editing:

- `docs/DESIGN.md`
- `docs/specs/05-file-manager.md`
- `frontend/src/FilesTab.tsx`
- `frontend/src/bridge.ts` and `frontend/src/types.ts`
- `src/sftp.zig`
- the SFTP handlers in `src/bridge.zig`
- the SFTP worker operations and transfer store in `src/sessions.zig`
- the SFTP container path in `src/integration.zig`
- `frontend/preview.html`; extend it, never delete or replace it

## Current Checkout Truth

The backend supports `RemotePath = {utf8:string}|{base64:string}`. The base64
form preserves raw server path bytes. An entry has `name`, `display`, `kind`,
`size`, `mtime`, `mode`, `uid`, `gid`, and `link_target`. `display` is UI text
only. Never build an operation path from it.

The exact entry kinds are `file`, `dir`, `symlink`, and `other`. The current
frontend checks for `directory`, so directory navigation is broken.

The bridge provides:

- `oars.sftp.ls {server_id,path}` → `{ok,entries,truncated}`
- `oars.sftp.stat {server_id,path}` → `{ok,entry}`
- `oars.sftp.read {server_id,path,offset,max}` → `{ok,base64,eof}`;
  `max` is 1–65,536 bytes
- `oars.sftp.write {server_id,path,offset,base64,transfer_id,total?}` →
  `{ok,written,done}`; the final chunk no-clobber renames the partial file
- `oars.sftp.save {server_id,path,base64}` → `{ok}` for an inline editor save;
  payloads are capped at 1 MiB and the backend requires atomic POSIX rename
- `oars.sftp.download {server_id,remote_path,local_path}` → `{ok,op_id}`;
  `local_path` must come from the native save dialog
- `oars.sftp.mkdir`, `rename`, and `chmod` are synchronous mutations
- `oars.sftp.rm` is synchronous for one item; `recursive:true` returns
  `{ok,op_id}`
- `oars.sftp.unzip {server_id,zip_path,dest_dir?,overwrite:false}` and
  `oars.sftp.zipDownload {server_id,paths,local_path}` return `{ok,op_id}`
- `oars.sftp.folderSize {server_id,path}` → `{ok,size}`
- `oars.sftp.poll {server_id}` returns a non-destructive transfer snapshot
- `oars.sftp.cancel {server_id,transfer_id}` requests cancellation

Mutations are audited in the session worker. ZIP extraction performs a bounded
central-directory preflight and refuses overwrite. Downloads and zip downloads
write local partial files and no-clobber rename them after success.

The frontend bridge is incomplete. It has wrappers for list, mkdir, simple
delete, rename, stat, log download, transfer poll, and cancel. Several results
use inline or `any` types. Add strict shared types and wrappers for every
implemented command.

The current editor contract also has a gap. Spec 05 requires changed-remote
file detection, but `oars.sftp.save` does not accept an expected identity. Do
not call a frontend-only stat-then-save sequence conflict-safe. Resolve this
before completing the editor: extend the backend with an expected size/mtime
or equivalent worker-side check and tests, or correct the spec with verified
evidence and state the remaining race honestly.

## Implementation Order

1. Add strict `RemotePath`, `SftpEntry`, listing, stat, read/write, operation,
   and transfer types. Remove SFTP `any` and inline duplicate entry types.
2. Add tested raw-path helpers. Join parent and child bytes without using
   `display`; keep breadcrumb path identities; hide dotfiles from the raw first
   byte; use a serialized raw identity as the React key.
3. Build a source-bound directory state machine. A late response for another
   server or path must not replace the current listing. Keep the prior list
   during refresh, cache successful directories in memory for 30 seconds, and
   expose `truncated` instead of pretending the listing is complete.
4. Replace the diagnostic table with the Oars file workspace: breadcrumbs,
   hidden toggle, Upload, Upload Dir, New Folder, view switcher, Add
   Application, selection actions, and list/grid/compact views. Use Lucide file
   icons, dense technical metadata, and the existing loading components. On
   mobile, use a labeled compact list with no horizontal page scroll.
5. Implement selection and keyboard behavior: click, modified range/toggle,
   `Cmd/Ctrl+A`, Escape, Enter to open a directory or text file, and Delete to
   open confirmation. Selection must survive view changes but clear when the
   directory identity changes.
6. Implement uploads from browser `File` objects and drag/drop. Read 64 KiB
   chunks, use a nonzero cryptographically random `transfer_id`, send exact
   offsets and total length, limit concurrency to three, and stop cleanly on
   cancel or failure. Feature-detect directory upload; do not fake it when the
   packaged WebView does not provide relative paths.
7. Implement file and selected-item downloads through `pickSaveFile` and the
   async transfer snapshot. A single file uses `download`; multiple selected
   paths use `zipDownload`. Dialog cancellation starts no backend operation.
8. Implement the text editor for valid UTF-8 files smaller than 1 MiB. Read in
   explicit-offset chunks, reject binary/invalid UTF-8 honestly, track dirty
   state, warn before closing, and complete the changed-remote contract before
   save. Never decode a raw filename to reconstruct its path.
9. Implement focused approval flows for mkdir, rename, chmod, upload, editor
   save, ZIP expansion, and delete. Recursive delete uses type-to-confirm.
   Every dialog shows the exact remote identity in safe display form and keeps
   raw bytes only in the payload.
10. Add folder-size requests, symlink/other states, permission failures, empty
    folders, ZIP expansion destination preview, and Add Application navigation
    to the current server's Deploy tab.
11. Add a bottom transfer drawer with active, done, failed, and canceled rows.
    Show bytes, total, progress, and error text. Poll only while transfers are
    active or recent; stop polling on server change and unmount.
12. Extend `frontend/preview.html` with deterministic root/nested/empty,
    unreadable, slow, truncated, non-UTF8, editor conflict, upload/download,
    archive, failure, and cancellation fixtures. Keep every existing preview
    mode working and record exact payloads without embedding file content.

## Design Rules

- This is an operational workspace, not a landing page. Keep the file list as
  the primary surface and use cards only for repeated transfer rows or dialogs.
- Keep the first directory load visibly active. Refreshes must not blank the
  workspace. Long upload, archive, and download work must always show progress.
- Use icon buttons for view modes and row actions, with tooltips. Use text
  buttons only for clear commands such as Upload or New Folder.
- Do not use emoji file icons, browser `confirm`, nested cards, or explanatory
  feature copy in the workspace.
- Match `docs/DESIGN.md` in light and dark themes. Reuse the modal, button,
  loading, status, and responsive patterns from Monitor, Logs, and VNC.

## Validation Gate

Do not mark spec 05 implemented until all of these pass:

- `zig build`
- `zig build test`
- `npm --prefix frontend test`
- `npm --prefix frontend run build`
- `git diff --check`
- Focused unit tests for raw-path joins, non-UTF8 identity, selection, stale
  directory responses, chunk offsets, progress, and editor conflict state
- Existing SFTP container integration plus a real frontend round trip for
  browse, upload, read, edit, rename, chmod, download, unzip, zip-download,
  cancel, and delete
- Desktop checks at 1440 × 1000 in light and dark themes
- Mobile checks at 390 × 844 with no overlapping controls or page overflow
- Exact backend payload checks for UTF-8 and base64 paths; no operation may use
  `display` as a path
- Upload and download success, failure, cancellation, duplicate-target, and
  disconnect behavior, with no abandoned local or remote partial file
- Editor valid UTF-8, binary, too-large, dirty-close, changed-remote, save
  success, unsupported atomic rename, and permission failure states
- Empty, unreadable, slow, truncated, symlink, archive-rejection, and recursive
  delete states
- No console errors, stale data, leaked poller, secret/file-content recording,
  layout shift, text overlap, or frozen-looking network state

After validation, update `docs/specs/05-file-manager.md`,
`docs/specs/README.md`, `docs/ROADMAP.md`, and `docs/HANDOVER.md` with current
checkout evidence only. Spec 12 is complete; do not weaken its VNC transport,
credential, setup, or live input checks while implementing the file manager.
