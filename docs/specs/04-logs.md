# Spec 04 — Log Management

**Status:** ✅ v1 frontend + backend implemented · **Depends on:** 02 (exec/follow) · **Spec owner:** core + frontend

## 1. Overview

"Find the log" is the job. Oars scans documented locations, groups the log
files it can discover (with size + last-write stamps so the active one is obvious), and
lets the user read, search, follow, download, or truncate it — no SSH, no
path guessing.

## 2. Goals / non-goals

**Goals**
- Auto-discover log sources, grouped (Web Servers / Runtime & Apps / System / Custom).
- Viewer with 200/500/1,000/5,000-line history, search within loaded lines.
- Follow = live tail; Download whole file; Clear (truncate) with confirm.
- Manual path add, persisted per server.
- Honest failure when a file can't be read.

**Non-goals**
- No fleet-wide search, no aggregation/indexing/retention, no alerting,
  no rotated/compressed archive reading (v1) — the spec stays a viewer.

## 3. User stories

- I open Logs on a server and see 28 sources; the one written 3 minutes ago stands out.
- I search a checkout error across 1,000 lines instead of re-running grep.
- I follow nginx access.log while I reproduce the bug.
- I download a log to attach to a ticket; I clear a 4 GB app log after confirming.

## 4. UI/UX

### 4.1 Logs view layout
- Left panel: **Log Sources** — search box, group headings, rows `name · size · last-write` (e.g. "Nginx · access · 105 KB · 3m"). Bottom: manual path input + add.
- Right panel: **viewer** — toolbar (source path, Follow toggle, line-count select 200/500/1k/5k, search box, Download, Clear), mono log lines, auto-scroll while following.
- Unreadable source: row shows a lock/error icon; opening it shows the failure reason (e.g. "Permission denied — connect as root or check file ACLs").

### 4.2 States
- Nothing scanned yet → "Scan for logs" CTA; scan is cached per session (re-scan button + auto-rescan on open if > 60 s old).
- Following → Live badge + "waiting for new lines"; click again to stop.
- Search matches highlighted within loaded lines; "N matches" count.
- Clear → confirm dialog: "This truncates the file on the server. Permanent. Download first if needed."

## 5. Bridge API

### `oars.logs.scan` `{server_id}` → sources
```json
{"ok":true,"sources":[
  {"path":"/var/log/nginx/access.log","group":"web","name":"Nginx · access",
   "size":472000,"mtime_epoch":1754000000,"age_sec":92,"mode":420,"readable":true},
  {"path":"/var/log/auth.log","group":"system","name":"auth.log",
   "size":1200000,"mtime_epoch":1754000034,"age_sec":58,"mode":384,"readable":false}
],"partial":false,"reason":""}
```
- Scan implementation (one exec, cached 60 s per session): `%BEGIN_DATE%`
  carries the remote clock (ages are computed against it, never the local
  workstation clock); `%BEGIN_SCAN%` carries NUL-delimited records
  (`path\0size\0mtime\0mode\0`). Markers use `%%` escapes — busybox printf
  errors on `%B`-style directives and prints nothing (verified live), and
  `%%` works on both busybox and GNU.
- GNU `find -printf` form, and the busybox `-print0` + `stat` fallback,
  joined with `||` (not `;`) so a find without `-printf` fails over instead
  of emitting two streams. The trailing `printf '\0'` makes an empty tree
  parse as zero records rather than degrading to the bare-path fallback:
```
printf '%%BEGIN_DATE%%\n'; date +%s; printf '%%BEGIN_SCAN%%\n'; find <roots> -maxdepth 3 -type f -printf '%p\0%s\0%T@\0%m\0' 2>/dev/null || find <roots> -maxdepth 3 -type f -print0 2>/dev/null | while IFS= read -r -d '' p; do printf '%s\0' "$p"; (stat -c '%s %Y %a' "$p" 2>/dev/null || printf '0 0 0\n') | tr ' \n' '\000\000'; done; printf '\0'
```
  Roots = `/var/log` + user-added paths (shell-quoted). This keeps spaces
  and newlines in file names from corrupting record boundaries. The scan
  also includes known non-`.log` files such as syslog and distro-specific
  auth logs, PM2 paths from user-added `pm2 jlist` output, and user-added
  paths. Grouping: `nginx|apache` → web; `pm2` or `-out.log`/`-err.log`
  under app dirs → runtime; syslog/auth/kern → system; else custom.
- Cap discovery by entry count (500) and output bytes (1 MB); the response
  carries `partial:true` with a reason when bounds prevent a complete scan.
  Compute `age_sec` from the remote clock and clamp future mtimes to zero
  rather than mixing remote mtimes with the local workstation clock.
- Readability probe: one batched exec of `test -r <path> && echo 1 || echo 0;`
  per source (first 100 paths), mapped in order; unreadable → `readable:false`
  (root bypasses DAC, so chmod-000 files still read `true` on root sessions).
- `mode` is the permission bits (0o644 etc.); the frontend echoes it back in
  `oars.logs.clear`'s `expected` as the identity preview.

### `oars.logs.read` `{server_id, path, lines}` → `{ok, path, lines: [...], limited, binary}`
- `tail -n <lines>` (lines ∈ {200,500,1000,5000}); file size cap 64 MB read.
- `limited: true` means the byte or line-size safety limit cut the response. A
  file growing after a tail read is normal and does not make that result
  truncated.
- The backend sniffs text safety before JSON serialization. `binary:true`
  returns no rendered lines; the frontend offers the SFTP download path and
  disables search and Follow for that source.

### `oars.logs.follow` `{server_id, path}` → `{ok, channel}`
- `tail -n 100 -F <quoted-path>` (name-follow with retry) so the viewer follows
  the new file after normal log rotation; `-F` works on both GNU and busybox
  (verified live), so no capability fallback is needed. Output streams via
  `oars.ssh.poll` (channel kind `log`) and stops via `oars.ssh.closeChannel`.
- Add `oars.ssh.closeChannel` `{server_id, channel}` to the bridge (worker: send EOF, close, free).

### `oars.logs.clear` `{server_id, path, expected:{size,mtime,mode}}` → `{ok}`
- After confirmation, SFTP-`lstat` the path and reject symlinks and non-regular
  files. Open without truncation, `fstat` the handle, and compare the available
  size, modification time, and mode with the preview. A mismatch stops with a
  conflict. Set that open handle's size to zero with SFTP attributes, then
  audit the before/after size. Standard SFTP v3 does not expose inode/device
  identity, so this does not claim to defeat a malicious server-side race; a
  later remote `openat` helper would be needed for that stronger boundary.
### Download via native dialog + SFTP transfer
- `native-sdk.dialog.saveFile` chooses the local path. The frontend then uses
  `oars.sftp.download`, `oars.sftp.poll`, and `oars.sftp.cancel`. It never
  streams a whole file through the terminal JSON string path: logs can contain
  non-UTF-8 bytes and can exceed the bridge response budget.

### `oars.logs.addSource` `{server_id, path}` → `{ok}` — persists to `logs.json` per server.

## 6. Zig core design

- `src/logs.zig` — scan/group/parse logic (pure functions + fixtures), source store (`<data>/logs.json` keyed by server_id), follow-channel helper reusing the session worker's exec path.
- Download uses the existing worker-owned SFTP transfer after a native save
  dialog. The frontend receives progress metadata, not file contents.
- No new threads: everything rides the session worker (scan/read = short execs; follow = exec channel).

## 7. Data model

- Per-server added paths: `<data>/logs.json` `{server_id: [paths]}`.
- Nothing else persisted — logs live on the server, by design.

## 8. Security

- Read-only by default; Clear is the only mutating action (confirm + audit).
- SSH exec accepts a shell command string, not argv. Every dynamic path uses
  the shared POSIX-shell quoting function. SFTP operations pass path bytes to
  libssh2 and do not invoke a shell.

## 9. Performance

- Scan ≤ 2 s on typical servers; cached.
- Follow streaming rides the poll budget; high-volume logs degrade to `dropped` warnings (visible in the viewer).
- 5,000-line loads render as a single windowed pass (mono rows, virtualization if needed).

## 10. Edge cases

- File deleted while following → channel EOF; viewer shows "source disappeared".
- File rotated (`access.log` → `access.log.1`) → name-follow reopens the new
  path. Descriptor-follow fallback shows that it still points at the old inode.
- Binary/garbage content → sniff first 256 bytes; offer "download instead of render".
- Unreadable → `readable:false` + reason; never a spinner.
- Huge single line → clamp line render length (64 KB) with "line truncated" marker.

## 11. Testing

- Unit: grouping rules, NUL-delimited fixture parses, remote-clock age math,
  scan bounds, path validation, scan-cache freshness/invalidation, source-store
  persistence/dedupe, shell-quote round-trip through a real `/bin/sh`, and the
  scan command's shape (`%%`-escaped markers, `||`-joined fallback).
- Integration (container, `scripts/integration-test.sh`): create logs in the
  sshd container (nginx-style + PM2-style), `addSource` the tree, scan →
  verify grouping/stamps/readability → read → missing-file failure → follow →
  append a line → verify the stream (kind `log`) → clear with a STALE preview
  → conflict refused → re-scan (addSource invalidates the cache) → clear with
  the fresh preview → verify truncated + audit entry → closeChannel.
- Frontend unit: absolute byte cursor selection and source-bound async request
  identity (`npm test`).
- Browser (2026-08-07): desktop light/dark and 390×844 mobile; grouped scan,
  5,000-line virtualization, search, Unicode follow cursors, dropped bytes,
  EOF/source reset, stale read/follow rejection, binary download-only state,
  and clean console.

## 12. Acceptance criteria

- [x] Scan groups real log layouts and stamps size/last-write correctly
      (verified against the busybox container; the GNU `-printf` form is
      documented from findutils and shares the identical record format).
- [x] Read/follow/clear work against the test container; download uses the
      shared SFTP transfer and never streams file contents through the JSON bridge.
- [x] Unreadable/missing files produce explicit errors, never hangs (root
      bypasses DAC, so `chmod 000` still reads as readable on root sessions;
      the readability mapping itself is unit-tested).
- [x] Manual paths persist across sessions (`logs.json` per server).
- [x] Parser/validator tests green.
- [x] Frontend source rail, separate searches, virtualized viewer, Follow,
      download progress, identity-bound Clear, and documented failure states
      pass desktop and mobile browser checks.

## 13. Research & References

- **Scan command** — `find /var/log -maxdepth 3 -type f -name '*.log'
  -printf '%p %s %T@\n'` verified against the GNU findutils man page
  (`https://man7.org/linux/man-pages/man1/find.1.html`): `-maxdepth`
  (descend at most N levels), `-type f` (regular files), `-name`
  (basename shell-pattern match), `-printf format` with directives `%p`
  (file's name), `%s` (size in bytes), `%T@` (last modification time as
  seconds since epoch **with fractional part** — the `@` form is
documented under `%Ak`-style directives). `2>/dev/null` suppresses
  permission errors; unreadable dirs simply yield fewer rows.
  **Correction:** space-delimited output cannot represent arbitrary Unix file
  names. The contract now uses NUL-delimited fields and parses them before JSON
  encoding. The `.log` filter was also widened so files such as `syslog` are
  not omitted. GNU documents `-printf`; it is not a POSIX `find` option, so the
  body now requires capability detection and a `-print0` plus `stat` fallback.
  **Correction (verified live, busybox 1.36 / alpine):** busybox `printf`
  errors on `%B`-style directives and prints nothing, so the marker lines must
  be emitted with `%%` escapes (`printf '%%BEGIN_DATE%%\n'`), which both
  busybox and GNU printf render as `%BEGIN_DATE%`. busybox `stat -c '%s %Y %a'`
  ends each record with a newline, so the fallback maps both spaces and the
  newline to NUL (`tr ' \n' '\000\000'`); a vanished file mid-scan falls back
  to `0 0 0` so a single race cannot fail the whole scan. GNU and busybox find
  are joined with `||` so a find without `-printf` fails over instead of
  emitting two streams; the trailing `printf '\0'` makes an empty tree parse
  as zero records.
- **`tail` read/follow** — verified against the GNU coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/tail-invocation.html`)
  and live on busybox:
  - `-n num` outputs the last num lines (spec: 200/500/1k/5k).
  - `-F` (`--follow=name` + `--retry`) works on both GNU and busybox
    (verified live), so the follow uses it directly; the descriptor-follow
    fallback in the draft was dropped. Without inotify, tail polls every
    1 s (`--sleep-interval`), which bounds our follow latency.
  - Truncation: "if the tracked file is determined to have shrunk, tail
    prints a message saying the file has been truncated and resumes
    tracking from the start" — the viewer re-reads to handle the same
    race from the client side.
- **Clear** — GNU `truncate` can set a file to zero, but a pathname-only
  command cannot bind the confirmation preview to the object later opened.
  The target therefore uses the vendored libssh2 SFTP handle APIs described in
  spec 05: `lstat`, reject symlinks/non-regular files, open WITHOUT
  truncation, `fstat` the handle, compare size/mtime/mode against the preview
  (a mismatch stops with a conflict), and set the size on that handle. The
  identity check is repeated against the OPEN handle. SFTP v3 has no
  inode/device field, so §5 states the remaining race limit instead of
  claiming a stable file identity. Verified live: a stale preview is refused;
  a fresh preview truncates and audits `before_size`/`after_size`.
- **PM2 log paths** — `pm2 jlist` JSON includes per-process log file
  paths (`pm_out_log_path`/`pm_err_log_path`); PM2 docs
  (`https://pm2.keymetrics.io/docs/usage/process-management/`, spec 03
  §13) confirm jlist as the machine interface. `pm2 jlist` itself is not
  invoked by the scan (no pm2 in the test container); PM2 paths arrive as
  user-added sources.
- **Readability probe** — `test -r <path>` is POSIX sh's documented
  readability check (`test(1)`, `-r` flag); run batched via exec.
- **Download transfer** — the shared SFTP worker writes the selected local
  file and reports bounded progress metadata through the bridge. Log contents
  never enter a JSON response.
- **Viewer virtualization** — TanStack Virtual's React adapter supplies the
  scroll-element virtualizer and dynamic row measurement used for 5,000-line
  loads (`https://tanstack.com/virtual/latest/docs/framework/react/react-virtual`).

Sources: GNU findutils find(1), GNU coreutils manual (tail, truncate),
PM2 docs, SDK bridge/root.zig, TanStack Virtual React docs.
