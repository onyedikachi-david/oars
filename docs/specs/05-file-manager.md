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

## 13. Research & References

- **libssh2 SFTP API** — verified against the vendored header
  `third_party/libssh2/include/libssh2_sftp.h`: `libssh2_sftp_init`
  L221, `libssh2_sftp_open_ex` L230 (with `LIBSSH2_SFTP_OPENDIR` flag
  L67 and the `libssh2_sftp_open`/`libssh2_sftp_opendir` macros L235–242),
  `libssh2_sftp_read` L255, `libssh2_sftp_readdir_ex` L258 (with
  `libssh2_sftp_readdir` macro L263), `libssh2_sftp_write` L267,
  `libssh2_sftp_fstat_ex` L283, `libssh2_sftp_rename_ex` L292 (default
  macro combines RENAME_OVERWRITE|ATOMIC|NATIVE — flags defined L70–73),
  `libssh2_sftp_unlink_ex` L315, `libssh2_sftp_shutdown` L222. The
  remaining ops (`mkdir`, `rmdir`, `chmod`, `stat`) are in the same
  header — the wrapper in `src/sftp.zig` calls these directly. SFTP
  itself is an SSH subsystem (RFC 4254 §6.5; the wire protocol is
  defined by the IETF draft-ietf-secsh-filexfer).
- **SFTP semantics** — rename across filesystems fails server-side with
  a cross-device error (SFTP status codes; the spec's copy+delete
  fallback is the standard remedy). Atomic editor saves via
  temp-file+rename are the same pattern sshd itself uses for
  authorized_keys updates (spec 08 §13).
- **`unzip`** — verified against the Info-ZIP unzip(1) man page
  (`https://manpages.ubuntu.com/manpages/noble/en/man1/unzip.1.html`):
  - `-d exdir` extracts to an arbitrary directory ✓.
  - **Correction/additions:** Info-ZIP unzip ≥ 5.50 strips `../` parent
    components from entry names **by default** ("For security reasons,
    unzip normally removes 'parent dir' path components ('../') from the
    names of extracted files", disabled only by `-:`), so the spec's
    entry-scan is defense-in-depth on top of unzip's own guard. Never
    pass `-:`; never pass `-K` (restores SUID/SGID bits, "cleared for
    security reasons" by default). Exit codes: 0 ok, 11 no matching
    files, 50 disk full — surface these to the user.
- **`du -sb`** — GNU coreutils `du` with `--block-size=1`/`-b` (bytes)
  and `-s` (summarize) per the coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/du-invocation.html`).
- **`zip -r`** — Info-ZIP zip(1) recursive flag (same source family as
  unzip; `zip -r` documented in `man zip`).
- **Chunk payloads** — 64 KB binary → base64 ≈ 87 KB JSON, under the
  SDK bridge's payload limit (`bridge/root.zig` L144,
  `payload_too_large`; the SDK example/docs use the same style).
- **Non-UTF8 names** — SFTP returns raw bytes; libssh2 gives byte
  strings (no decoding) — display escaping is client-side, bytes
  preserved (per §10).

Sources: `third_party/libssh2/include/libssh2_sftp.h`, Info-ZIP unzip(1),
GNU coreutils du(1), SDK bridge/root.zig.
