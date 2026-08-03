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
- No binary diffing, no FUSE mounting, and no archive creation in arbitrary
  formats. A cross-filesystem move is a separate copy-and-delete operation and
  always needs a new confirmation because it is not atomic.

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
- Opens UTF-8 text files smaller than 1 MB in an editor. Save compares the
  current size, modification time, and content hash with the version that was
  opened. A changed remote file causes a conflict prompt. Save writes a temp
  file in the same directory and requests the server's
  `posix-rename@openssh.com` extension through
  `libssh2_sftp_posix_rename_ex`;
  if the server cannot provide an atomic replacement, Oars fails safely and
  explains the limit.

### 4.3 Empty/error states
- Unreadable dir → error banner with reason.
- Slow FS (network) → spinner only on the active breadcrumb path; list is otherwise cached per directory for 30 s.
- Huge dir (> 5,000 entries) → windowed render.

## 5. Bridge API

SFTP runs on the session worker. Transfer calls are **async-op** style and
return an operation id. `oars.sftp.poll` returns a current state snapshot; file
bytes use the explicit-offset read/write calls rather than a consumptive event
stream.

All path parameters use `RemotePath = {utf8:string}|{base64:string}`. The
base64 form carries raw server bytes; `display` is escaped text for UI only.

### `oars.sftp.ls` `{server_id, path:RemotePath}` → `{ok, entries}`
```json
[{"name":{"utf8":"nginx.conf"},"display":"nginx.conf","kind":"file",
  "size":4096,"mtime":1754…,"mode":"rw-r--r--","uid":0,"gid":0,
  "link_target":null}]
```
- `link_target` for symlinks (readlink on demand).

### `oars.sftp.stat` `{server_id, path:RemotePath}` → entry
### `oars.sftp.read` `{server_id, path:RemotePath, offset, max}` → `{ok, base64, eof}` (64 KB chunks)
### `oars.sftp.write` `{server_id, path:RemotePath, offset, base64, transfer_id}` → `{ok, written}`
### `oars.sftp.download` `{server_id, remote_path:RemotePath, local_path, expected?}` → `{ok, op_id}`
- `local_path` must be the result of the native save dialog for this operation.
  The core owns the local file descriptor, streams SFTP bytes directly to it,
  uses a partial file, and no-clobber renames only after success.
### `oars.sftp.mkdir` `{server_id, path:RemotePath}` / `oars.sftp.rm` `{server_id, path:RemotePath, recursive?}` / `oars.sftp.rename` `{server_id, from:RemotePath, to:RemotePath}` / `oars.sftp.chmod` `{server_id, path:RemotePath, mode}`
- `rm` recursive → exec `rm -rf` (approval-gated) or recursive SFTP delete; v1 = recursive SFTP delete with per-entry progress.
### `oars.sftp.unzip` `{server_id, zip_path, dest_dir?, overwrite:false}`
- Before extraction, parse the ZIP central directory and reject absolute paths,
  `..` components, drive-letter paths, symlink or hard-link entries, duplicate
  paths, and file/directory conflicts. Enforce entry-count, total-uncompressed-
  size, per-entry-size, path-length, nesting-depth, and compression-ratio
  limits, and compare required space with the destination filesystem.
- Copy the archive into an owner-only staging directory, validate that staged
  byte sequence, and extract only that copy with overwrite disabled. Move the
  validated result into place only after the command succeeds. Overwrite is a
  separate conflict preview and confirmation.
### `oars.sftp.zipDownload` `{server_id, paths:RemotePath[], local_path}` → `{ok, op_id}`
- Create a uniquely named remote staging archive, download through the native
  writer, and remove the remote archive in success and failure cleanup. Never
  interpret `local_path` as a remote path.
### `oars.sftp.folderSize` `{server_id, path}` → exec `du -sb <path>` parsed; cached 5 min.
### `oars.sftp.poll` `{server_id}` → active transfers + bounded recent completed ops (op id, kind, path, bytes, total, status, error)
- This response is a non-destructive snapshot. Two views can poll it without
  consuming each other's progress.

Uploads (local → remote): frontend reads the local file (File API), starts one
approved transfer, and sends 64 KB chunks under its unguessable `transfer_id`.
The core writes a unique partial file and no-clobber renames it only after the
declared length and optional hash verify. Cancel stops the loop and deletes the
partial file.

## 6. Zig core design

- `src/sftp.zig` — thin wrapper over libssh2 SFTP (`sftp_init` once per session, guarded by the worker; ops executed on the worker thread via the existing op queue: new op kinds `sftp_ls/stat/read/write/…`).
- SFTP handles are session-scoped; opened per op and closed after (v1) — no handle caching.
- Transfer state: `SftpTransfer {op_id, kind, path, bytes_total, bytes_done, cancel_flag}` in a session-owned map (spin-locked).
- Chunk payloads: base64 in/out of the bridge (JSON-safe); 64 KB chunks ≈ 87 KB base64 — well within the 1 MB bridge budget.

## 7. Data model

- Nothing persisted server-side beyond what the user does. Client-side: no cache files; directory listing cache in memory only (30 s TTL).

## 8. Security

- All mutations (rm, write, chmod, unzip, rename) → confirm dialog; rm recursive → type-to-confirm.
- The SSH account's server permissions are the filesystem boundary. Normalize
  paths and reject malformed traversal, but do not claim a lexical home check
  is a sandbox because symlinks can cross it. Optional workspace-root mode must
  resolve every path on the server and block symlink escapes.
- Uploads overwrite only with `overwrite:true` explicitly set by the UI (default false → error `exists`).

## 9. Performance

- Start with 64 KB chunks and at most three transfers. Benchmark 100 MB upload
  and download on local and 100 ms-latency links before setting a throughput
  target or changing the chunk size.
- Directory listings windowed beyond 5,000 entries.

## 10. Edge cases

- SFTP not supported by server → clear error, offer exec fallback (no).
- Rename across filesystems → show a copy-and-delete plan with size, free-space
  check, second confirmation, progress, and partial-copy cleanup.
- Write to read-only file → perms error surfaced with current mode.
- Path with non-UTF8 bytes → `RemotePath.base64` preserves bytes and the UI
  uses escaped `display` text; no operation reconstructs a path from display.
- Transfer interrupted (disconnect) → drawer shows failed; partial file named `<name>.partial` (upload) and deleted on cancel.
- ZIP extraction follows the central-directory and staging rules in §5. Never
  rely on `unzip` stripping `../` because symlink and conflicting-entry attacks
  need separate checks.

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
  header. The proposed `src/sftp.zig` wrapper will call these APIs; that file
  does not exist in the current checkout. SFTP
  itself is an SSH subsystem (RFC 4254 §6.5; the wire protocol is
  defined by the IETF draft-ietf-secsh-filexfer).
- **SFTP rename semantics** — the vendored
  `libssh2_sftp_posix_rename_ex(3)` manual says it implements the
  `posix-rename@openssh.com` extension and returns
  `LIBSSH2_FX_OP_UNSUPPORTED` when the server lacks it. The editor requires
  that extension for atomic replacement. Cross-filesystem moves are planned as
  explicit copy-and-delete jobs because a same-filesystem atomic rename cannot
  provide that behavior.
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
- **ZIP validation** — PKWARE maintains the authoritative ZIP Application Note
  (`https://support.pkware.com/pkzip/appnote`). The central directory carries
  entry names, compressed and uncompressed sizes, offsets, and external file
  attributes. Those fields enable the path/type/size preflight, but limits such
  as maximum expanded bytes and compression ratio are Oars resource guards,
  not guarantees supplied by the format.
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

Sources: `third_party/libssh2/include/libssh2_sftp.h`, the vendored
`libssh2_sftp_posix_rename_ex(3)` manual, PKWARE ZIP Application Note,
Info-ZIP unzip(1), GNU coreutils du(1), SDK bridge/root.zig.
