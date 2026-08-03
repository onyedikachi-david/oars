# Spec 05 — File Manager (SFTP)

**Status:** 📋 · **Depends on:** 02 (session), libssh2 SFTP · **Spec owner:** core + frontend

## 1. Overview

The server's filesystem as folders you click: browse, upload, download,
edit, rename, chmod, unzip — over the SFTP subsystem of the SSH session
already open. No scp, no separate client, no agent.

## 2. Goals / non-goals

**Goals**
- Browse with breadcrumbs; hidden-items (dotfile) toggle.
- Upload/download with per-file progress and cancel; drag-and-drop both directions.
- Inline text editor with save-back; Expand ZIP in place; multi-select download-as-zip.
- Folder sizes on demand; permission/size/mtime columns; symlink handling.
- Reuse the same transfer machinery for logs download (spec 04).

**Non-goals**
- No binary diffing, no remote rename across filesystems (SFTP rename fails → fallback copy+delete), no FUSE mounting, no archive *creation* in arbitrary formats (zip only).

## 3. User stories

- I drag `release.zip` onto the browser and it lands in `/var/www/html`.
- I open `.env`, change a line, hit Save — it writes back in place.
- I select 12 files and download them as one zip.
- I right-click a zip and Expand it; a folder named after the zip appears.
- I check what's eating disk: folder sizes computed on demand.

## 4. UI/UX

### 4.1 Layout
- Toolbar: path breadcrumbs · hidden-items toggle · Upload / Upload Dir / New Folder / view switcher (grid · list · compact) · Add Application (→ spec 07).
- Dual-pane optional layout (local ↔ remote) for drag-and-drop; v1 = single remote pane + system file dialog for uploads, HTML5 drag from Finder for drops.
- Rows: icon (type-colored) · name · size · mtime · permissions (rwxr-xr-x) · owner.
- Selection: click, shift-click range, `⌘A`; selection toolbar (Download as zip, Delete (confirm), Copy Path, Rename, Open in Editor).
- Transfers: bottom drawer with per-file rows (name, progress bar, speed, cancel); collapses when idle.

### 4.2 Editor
- Opens text files (sniff: UTF-8-ish, size < 1 MB) in a modal with mono font, Save / Reload / Cancel; dirty indicator; save writes via SFTP in place (atomic: temp file + rename to avoid truncation mid-write).

### 4.3 Empty/error states
- Unreadable dir → error banner with reason.
- Slow FS (network) → spinner only on the active breadcrumb path; list is otherwise cached per directory for 30 s.
- Huge dir (> 5,000 entries) → windowed render.

## 5. Bridge API

SFTP runs on the session worker; bridge calls are **async-op** style: each
call returns an op id; progress/results arrive on `oars.sftp.poll` (cursor
streams, same pattern as ssh).

### `oars.sftp.ls` `{server_id, path}` → `{ok, entries}`
```json
[{"name":"nginx.conf","kind":"file","size":4096,"mtime":1754…,"mode":"rw-r--r--","uid":0,"gid":0,"link_target":null}]
```
- `link_target` for symlinks (readlink on demand).

### `oars.sftp.stat` `{server_id, path}` → entry
### `oars.sftp.read` `{server_id, path, offset, max}` → `{ok, base64, eof}` (64 KB chunks)
### `oars.sftp.write` `{server_id, path, offset, base64}` → `{ok, written}`
### `oars.sftp.mkdir` `{server_id, path}` / `oars.sftp.rm` `{server_id, path, recursive?}` / `oars.sftp.rename` `{server_id, from, to}` / `oars.sftp.chmod` `{server_id, path, mode}`
- `rm` recursive → exec `rm -rf` (approval-gated) or recursive SFTP delete; v1 = recursive SFTP delete with per-entry progress.
### `oars.sftp.unzip` `{server_id, zip_path, dest_dir?}` → exec `unzip -o <zip> -d <dest>` streamed (requires `unzip` on server; missing → offer AI-terminal install suggestion)
### `oars.sftp.zipDownload` `{server_id, paths[], dest_zip}` → exec `zip -r` on server, then stream download.
### `oars.sftp.folderSize` `{server_id, path}` → exec `du -sb <path>` parsed; cached 5 min.
### `oars.sftp.poll` `{server_id}` → active transfers + completed ops (op id, kind, path, bytes, total, status, error)

Uploads (local → remote): frontend reads the local file (File API),
chunks 64 KB, `oars.sftp.write` sequentially; per-chunk progress updated
in the drawer; cancel stops the loop and deletes the partial file.

## 6. Zig core design

- `src/sftp.zig` — thin wrapper over libssh2 SFTP (`sftp_init` once per session, guarded by the worker; ops executed on the worker thread via the existing op queue: new op kinds `sftp_ls/stat/read/write/…`).
- SFTP handles are session-scoped; opened per op and closed after (v1) — no handle caching.
- Transfer state: `SftpTransfer {op_id, kind, path, bytes_total, bytes_done, cancel_flag}` in a session-owned map (spin-locked).
- Chunk payloads: base64 in/out of the bridge (JSON-safe); 64 KB chunks ≈ 87 KB base64 — well within the 1 MB bridge budget.

## 7. Data model

- Nothing persisted server-side beyond what the user does. Client-side: no cache files; directory listing cache in memory only (30 s TTL).

## 8. Security

- All mutations (rm, write, chmod, unzip, rename) → confirm dialog; rm recursive → type-to-confirm.
- Path validation: reject `..` components that escape the session user's home unless explicitly allowed (root sessions are the user's choice).
- Uploads overwrite only with `overwrite:true` explicitly set by the UI (default false → error `exists`).

## 9. Performance

- 64 KB chunks; concurrent transfers ≤ 3; a 100 MB file ≈ 1,600 round trips — with local loopback bridge + SSH this should sustain > 5 MB/s; verify and raise chunk size if below 2 MB/s (bridge round trip ~1–2 ms local).
- Directory listings windowed beyond 5,000 entries.

## 10. Edge cases

- SFTP not supported by server → clear error, offer exec fallback (no).
- Rename across devices → `cross-device` error → UI offers copy+delete.
- Write to read-only file → perms error surfaced with current mode.
- Path with non-UTF8 bytes → bytes preserved, display escaped.
- Transfer interrupted (disconnect) → drawer shows failed; partial file named `<name>.partial` (upload) and deleted on cancel.
- Zip with paths escaping dest (`../`) → `unzip` protection: use `-d` with validated dest; scan entries first, reject escapes.

## 11. Testing

- Unit: path validation, base64 chunk codec, transfer state machine.
- Integration (container): upload → ls → read back → edit → rename → chmod → rm; unzip a fixture; zip-download round trip; symlink listing.
- Manual: drag-drop from Finder, cancel mid-transfer, editor save.

## 12. Acceptance criteria

- [ ] Full CRUD round trip against the test container over SFTP.
- [ ] Drag-drop upload + download-as-zip work.
- [ ] Editor saves atomically (no truncation on failure).
- [ ] Transfers show progress and can be cancelled cleanly.
- [ ] All mutations are confirm-gated and audited.
