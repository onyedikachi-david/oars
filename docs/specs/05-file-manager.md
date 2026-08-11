# Spec 05 — File Manager (SFTP)

**Status:** ✅ implemented · **Depends on:** 02 (session), libssh2 SFTP · **Spec owner:** core + frontend

## 1. Overview

A two-pane file workspace: local files on the left and the connected server on
the right. Remote operations use the SFTP subsystem of the SSH session that is
already open. Direct pane-to-pane transfers stay in the native core, so file
bytes do not pass through the JSON WebView bridge. No scp, separate client, or
server agent is required.

## 2. Goals / non-goals

**Goals**
- Browse with breadcrumbs; hidden-items (dotfile) toggle.
- Browse a local folder beside the remote folder. Upload selected local files
  to the current remote folder and download selected remote files to the
  current local folder.
- Keep Finder picker, drag-and-drop, and native save-dialog flows as fallbacks.
  Show per-file progress and cancel for both directions.
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
- Desktop: two persistent panes. The left pane lists a native local folder. The
  right pane lists the current SFTP folder. Each pane has its own path,
  refresh, selection, loading, empty, and error state. Compact layouts stack
  the panes without horizontal page scrolling.
- Local header: choose folder · parent · refresh. A selected local file exposes
  **Upload to remote** with an approval that shows the exact remote target.
- Remote pane: use the same header, path bar, three-column list, row height,
  typography, hover, selection, loading, error, and empty states as the local
  pane. Remote-only controls are in the header, path bar, and selection bar;
  they do not create a second visual system. A selected remote item exposes
  **Download to local** when a local folder is open; otherwise Oars uses the
  native save dialog.
- Rows: type-colored icon · name and kind · size · mtime. Remote permissions
  and link targets appear as secondary row metadata without changing the
  shared local/remote column grid.
- Selection: click, shift-click range, `⌘A`; selection toolbar (Download as zip, Delete (confirm), Copy Path, Rename, Open in Editor).
- Transfers: bottom drawer with per-file rows (name, progress bar, speed, cancel); collapses when idle.

### 4.2 Editor
- Opens UTF-8 text files smaller than 1 MB in an editor. Save compares the
  current size, modification time, and content hash with the version that was
  opened. The worker makes this check before it writes the temporary file and
  again immediately before rename. A detected remote change causes a conflict
  prompt, with reload as the safe action. Save writes the temporary file in the
  same directory and requests the server's
  `posix-rename@openssh.com` extension through
  `libssh2_sftp_posix_rename_ex`;
  if the server cannot provide an atomic replacement, Oars fails safely and
  explains the limit.
- The extension makes replacement atomic, but it does not implement
  compare-and-swap and does not accept an expected file identity. A remote
  writer can still change the target in the final network round trip between
  the second identity check and rename. A stronger guarantee needs a
  server-side helper or lock protocol, which is outside the agentless SFTP
  design. The UI never offers a blind force-overwrite action.

### 4.3 Empty/error states
- Unreadable dir → error banner with reason.
- Slow FS (network) → spinner only on the active breadcrumb path; list is otherwise cached per directory for 30 s.
- Huge dir (> 5,000 entries) → windowed render.

## 5. Bridge API

SFTP runs on the session worker. Transfer calls are **async-op** style and
return an operation id. `oars.sftp.poll` returns a current state snapshot; file
bytes use the explicit-offset read/write calls rather than a consumptive event
stream.

Remote path parameters use `RemotePath = {utf8:string}|{base64:string}`. The
base64 form carries raw server bytes; `display` is escaped text for UI only.

### `oars.local.ls` `{path}` → `{ok, entries, truncated}`
- `path` is an absolute native path selected or reached from the trusted
  packaged UI. The core lists at most 5,000 entries, does not follow symlinks,
  does not read file contents, and returns folders first.
- An entry has `name`, absolute `path`, `kind`, `size`, and `mtime`.

### `oars.sftp.ls` `{server_id, path:RemotePath}` → `{ok, entries}`
```json
[{"name":{"utf8":"nginx.conf"},"display":"nginx.conf","kind":"file",
  "size":4096,"mtime":1754…,"mode":"rw-r--r--","uid":0,"gid":0,
  "link_target":null}]
```
- `link_target` for symlinks (readlink on demand).

### `oars.sftp.stat` `{server_id, path:RemotePath}` → entry
### `oars.sftp.read` `{server_id, path:RemotePath, offset, max}` → `{ok, base64, eof}` (64 KB chunks)
### `oars.sftp.write` `{server_id, path:RemotePath, offset, base64, transfer_id, total?}` → `{ok, written, done}`
- Chunks stream into `<path>.partial`; the chunk whose written size reaches
  `total` (default `offset + decoded length` for single-shot writes) is the
  final chunk: no-clobber rename into `path` (a target that appeared
  meanwhile is a conflict, not an overwrite).
- `transfer_id` is the frontend's unguessable id; the first chunk registers
  the transfer, `oars.sftp.cancel` stops the loop and deletes the partial.
### `oars.sftp.download` `{server_id, remote_path:RemotePath, local_path, expected?}` → `{ok, op_id}`
- `local_path` is either a destination inside the local pane or the result of
  the native save dialog for this operation.
  The core owns the local file descriptor, streams SFTP bytes directly to it,
  uses a partial file, and no-clobber renames only after success.
### `oars.sftp.uploadLocal` `{server_id, local_path, remote_path:RemotePath}` → `{ok, op_id}`
- The session worker opens the selected native file and streams it straight to
  a unique remote partial file. It updates the shared transfer snapshot and
  no-clobber renames only after the declared local length is written.
### `oars.sftp.rm` `{server_id, path:RemotePath, recursive?}`
- Plain delete is synchronous → `{ok}`; recursive deletes run as an async
  transfer (`{ok, op_id}`) with per-entry progress and cancel.
### `oars.sftp.mkdir` `{server_id, path:RemotePath}` → `{ok}`
### `oars.sftp.rename` `{server_id, from:RemotePath, to:RemotePath}` → `{ok}`
### `oars.sftp.chmod` `{server_id, path:RemotePath, mode}` → `{ok}` (permission bits only, `mode & 0o7777`)
### `oars.sftp.save` `{server_id, path:RemotePath, base64, expected_size?, expected_mtime?, expected_sha256?}` → `{ok}`
- The editor supplies all three expected identity fields. The worker checks
  them before the temporary write and immediately before
  `posix-rename@openssh.com`. It refuses with a clear message on identity
  conflict or when the server lacks the extension.
### `oars.sftp.unzip` `{server_id, zip_path, dest_dir?, overwrite:false}` → `{ok, op_id}`
- Before extraction, parse the ZIP central directory and reject absolute paths,
  `..` components, drive-letter paths, symlink or hard-link entries, duplicate
  paths, and file/directory conflicts. Enforce entry-count, total-uncompressed-
  size, per-entry-size, path-length, nesting-depth, and compression-ratio
  limits, and compare required space with the destination filesystem.
- Copy the archive into an owner-only staging directory, validate that staged
  byte sequence, and extract only that copy with overwrite disabled. Move the
  validated result into place only after the command succeeds. Overwrite is a
  separate conflict preview and confirmation.
- `dest_dir` defaults to `<dir>/<zip stem>` (a folder named after the
  archive appears next to it). `overwrite:true` is refused; every target
  must be absent before anything is written.
### `oars.sftp.zipDownload` `{server_id, paths:RemotePath[], local_path}` → `{ok, op_id}`
- Create a uniquely named remote staging archive, download through the native
  writer, and remove the remote archive in success and failure cleanup. Never
  interpret `local_path` as a remote path.
### `oars.sftp.folderSize` `{server_id, path}` → `{ok, size}` — `du -sb <path>` parsed; cached 5 min.
### `oars.sftp.poll` `{server_id}` → `{ok, transfers:[{id, kind, path, bytes, total, status, error}]}`
- This response is a non-destructive snapshot. Two views can poll it without
  consuming each other's progress.
### `oars.sftp.cancel` `{server_id, transfer_id}` → `{ok}`

Uploads from the native local pane use `oars.sftp.uploadLocal`; bytes stay
between the local file descriptor and libssh2 on the session worker. Finder
drop and browser-picker uploads use the File API fallback: the frontend sends
64 KB chunks under an unguessable `transfer_id`. Both paths use a unique remote
partial file, no-clobber completion, transfer polling, and cleanup on cancel.

## 6. Zig core design

- `src/sftp.zig` — thin wrapper over libssh2 SFTP (`sftp_init` once per session, guarded by the worker; ops executed on the worker thread via the existing op queue: new op kinds `sftp_ls/stat/read/write/…`).
- SFTP handles are session-scoped; opened per op and closed after (v1) — no handle caching.
- Transfer state: `SftpTransfer {op_id, kind, path, bytes_total, bytes_done, cancel_flag}` in a session-owned map (spin-locked).
- Direct pane transfers carry metadata only through JSON. File API fallback
  uploads and editor reads use base64 chunks; 64 KB binary is about 87 KB in
  base64 and stays within the 1 MB bridge budget.

## 7. Data model

- Nothing is persisted server-side beyond what the user does. Oars creates no
  client-side cache files. Remote directory listings use a 30-second in-memory
  cache. The local pane reloads after completed downloads.

## 8. Security

- All mutations (rm, write, chmod, unzip, rename) → confirm dialog; rm recursive → type-to-confirm.
- The SSH account's server permissions are the filesystem boundary. Normalize
  paths and reject malformed traversal, but do not claim a lexical home check
  is a sandbox because symlinks can cross it. Optional workspace-root mode must
  resolve every path on the server and block symlink escapes.
- Uploads and downloads do not overwrite. Existing targets cause a conflict;
  there is no `overwrite:true` path in the shipped UI.
- Custom local-file commands are accepted only from the trusted packaged app
  origin under the bridge policy. They reject relative paths, NUL bytes,
  overlong paths, and symlink following. A future untrusted or remotely hosted
  frontend requires an opaque native capability instead of raw absolute paths.

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
- Manual: choose and navigate a local folder; upload local → remote; download
  remote → the current local folder; drag-drop from Finder; cancel
  mid-transfer; editor save; verify matching local/remote list geometry on
  desktop; verify light, dark, and 390 px stacked layouts.

## 12. Acceptance criteria

- [x] Full CRUD round trip against the test container over SFTP.
- [x] Local and remote folders render as a functional split workspace.
- [x] Direct local-to-remote transfer avoids base64 and reports progress.
- [x] Remote downloads target the selected local folder and refresh it on completion.
- [x] Drag-drop upload and download-as-zip work through the frontend UI.
- [x] Editor saves atomically (no truncation on failure).
- [x] Transfers show progress and can be cancelled cleanly in the drawer.
- [x] All mutations are audited and have focused confirmation dialogs.

## 13. Research & References

- **Native local directory picker** — verified against the installed Native
  SDK capability guide: `native-sdk.dialog.openFile` is a policy-controlled
  native capability (`bridge-security-native-capabilities.md` L115 and
  L133), and its options include `allowDirectories` (L188–192). The installed
  macOS host maps that option to `NSOpenPanel.canChooseDirectories`
  (`appkit_host.m` L12270–12271). Oars uses this native dialog to choose the
  local pane's starting folder; the custom listing command remains restricted
  to the trusted `zero://app` bridge origin.
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
  header. The implemented `src/sftp.zig` wrapper calls these APIs. SFTP itself
  is an SSH subsystem (RFC 4254 §6.5; the wire protocol is
  defined by the IETF draft-ietf-secsh-filexfer).
- **SFTP rename semantics** — the vendored
  `libssh2_sftp_posix_rename_ex(3)` manual says it implements the
  `posix-rename@openssh.com` extension and returns
  `LIBSSH2_FX_OP_UNSUPPORTED` when the server lacks it. The editor requires
  that extension for atomic replacement. Its signature has source and
  destination paths only; it has no expected identity or compare-and-swap
  condition. Cross-filesystem moves are planned as explicit copy-and-delete
  jobs because a same-filesystem atomic rename cannot provide that behavior.
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

### Corrections / verified in the implementation

- **`zip` is NOT preinstalled on the alpine dev container** (busybox has
  `unzip` and `du`, not `zip`). `scripts/dev-sshd/Dockerfile` now installs
  `zip` for the zipDownload integration path. `du -sb` works on busybox
  and prints `bytes<TAB>path`; busybox `ls` exits **1** (not GNU's 2) on
  missing paths.
- **`std.zip.EndRecord.findBuffer` is compile-broken in Zig 0.16.0**
  (`error.EndOfStream` outside its error set) — the EOCD scan
  (`findEndRecord`) is implemented in `src/sftp.zig` and rejects zip64.
  `std.compress.flate.Decompress.init(&reader, .raw, &window)` +
  `.reader.readSliceShort(buf)` is the working 0.16 extraction pattern.
- **Editor save uses `libssh2_sftp_posix_rename_ex`** (posix-rename
  extension); `LIBSSH2_FX_OP_UNSUPPORTED` → the worker refuses with a
  clear message. The worker compares size, mtime, and SHA-256 before writing
  the temporary file and again immediately before rename (spec §4.2).
- **`write` carries an optional `total`** — the worker renames
  `<path>.partial` into place only once the written size reaches it.
- **`rm` recursive is a recursive SFTP delete** (per-entry progress on
  the transfer record, cancelable), not `rm -rf`.
- **`sftpRm` takes an optional outcome** — synchronous single-item removal
  supplies one, while recursive removal passes `null` and reports through the
  transfer record. No stack or dummy outcome can outlive a bridge handler.
- **Zig 0.16 API drift caught while wiring the handlers:**
  `Io.File.writeStreamingAll` (no `writeAll`), `std.mem.trimStart` (no
  `trimLeft`), `Io.Dir.renameAbsolute` is a namespace function,
  `Channel.exitStatus()` returns plain `i32` (no `orelse`),
  `readFileAlloc` takes an `Io.Limit` (`.limited(n)`), and variadic
  `@intCast` into C `unsigned int` params needs `@as(c_uint, ...)`.
- **Two worker bugs found by the integration test:** `sftpMkdirP` walked
  absolute paths as relative components (SFTP paths are cwd-relative — a
  `defer`-in-loop also dangled the component list; both fixed) and
  `commonDir` returned the file path itself for single-path
  zipDownloads (`cd <file>` → zip exit 2) — it now returns the
  containing directory. The stored-zip fixture's local header had two
  stray bytes (extra-length field), shifting extracted data.

Sources: `third_party/libssh2/include/libssh2_sftp.h`, the vendored
`libssh2_sftp_posix_rename_ex(3)` manual, PKWARE ZIP Application Note,
Info-ZIP unzip(1), GNU coreutils du(1), SDK bridge/root.zig.
