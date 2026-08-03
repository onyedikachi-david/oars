# Spec 04 — Log Management

**Status:** 📋 · **Depends on:** 02 (exec/follow) · **Spec owner:** core + frontend

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
   "size":472000,"mtime_epoch":1754000000,"age_sec":92,"readable":true},
  {"path":"/var/log/auth.log","group":"system","name":"auth.log",
   "size":1.2e6,"mtime_epoch":1754000034,"age_sec":58,"readable":false}
]}
```
- Scan implementation (exec, cached 60 s):
```
find /var/log -maxdepth 3 -type f -printf '%p\0%s\0%T@\0' 2>/dev/null
```
The probe also reads remote `date +%s`. The parser handles the NUL-delimited
records before it builds JSON. This keeps
spaces and newlines in file names from corrupting record boundaries. The scan
also includes known non-`.log` files such as syslog and distro-specific auth
logs, PM2 paths from `pm2 jlist`, and user-added paths. Grouping:
`nginx|apache` → web; `pm2|out|err` under app dirs → runtime; syslog/auth/kern → system; else custom.
- GNU `find -printf` is capability-detected. On BusyBox or another find without
  `-printf`, use `find ... -print0` and obtain size and modification time with a
  detected `stat` format. If neither safe NUL-delimited path works, list only
  configured and known fixed paths and report partial discovery.
- Cap discovery by entry count and output bytes. Return `partial:true` with a
  reason when permissions, capability limits, or bounds prevent a complete
  scan. Compute `age_sec` from the remote clock and clamp future mtimes to zero
  rather than mixing remote mtimes with the local workstation clock.
- Readability probe: `test -r <path>` per source (batched; only for top-level scan results).

### `oars.logs.read` `{server_id, path, lines}` → `{ok, path, lines: [...], limited}`
- `tail -n <lines>` (lines ∈ {200,500,1000,5000}); file size cap 64 MB read.
- `limited: true` means the byte or line-size safety limit cut the response. A
  file growing after a tail read is normal and does not make that result
  truncated.

### `oars.logs.follow` `{server_id, path}` → `{ok, channel}`
- Prefer `tail -n 100 --follow=name --retry <quoted-path>` so the viewer follows
  the new file after normal log rotation. Detect support first and fall back to
  descriptor follow with a clear "reopen after rotation" state. Output streams
  via `oars.ssh.poll` (channel kind `log`).
- Add `oars.ssh.closeChannel` `{server_id, channel}` to the bridge (worker: send EOF, close, free).

### `oars.logs.clear` `{server_id, path, expected:{size,mtime,mode}}` → `{ok}`
- After confirmation, SFTP-`lstat` the path and reject symlinks and non-regular
  files. Open without truncation, `fstat` the handle, and compare the available
  size, modification time, and mode with the preview. A mismatch stops with a
  conflict. Set that open handle's size to zero with SFTP attributes, then
  audit the before/after size. Standard SFTP v3 does not expose inode/device
  identity, so this does not claim to defeat a malicious server-side race; a
  later remote `openat` helper would be needed for that stronger boundary.
### `oars.logs.download` `{server_id, path}` → `{ok, job}` 
- Reuse the binary SFTP transfer in spec 05. Do not stream a whole file through
  the terminal JSON string path: logs can contain non-UTF-8 bytes and can be
  larger than the bridge response budget.

### `oars.logs.addSource` `{server_id, path}` → `{ok}` — persists to `logs.json` per server.

## 6. Zig core design

- `src/logs.zig` — scan/group/parse logic (pure functions + fixtures), source store (`<data>/logs.json` keyed by server_id), follow-channel helper reusing the session worker's exec path.
- Download uses a native local-file writer after a save dialog and SFTP reads
  from the worker. The bridge carries bounded base64 chunks and never exposes
  a general write-any-path command to untrusted origins.
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
  scan bounds, path validation, and clear identity conflicts.
- Integration: create logs in the sshd container (nginx-style + PM2-style), scan → read → follow → write more lines → verify stream; clear → verify truncated; unreadable file (chmod 000) → verify failure surface.
- Manual: 5k-line search, download, rotation behavior.

## 12. Acceptance criteria

- [ ] Scan groups real log layouts and stamps size/last-write correctly.
- [ ] Read/follow/search/clear/download all work against the test container.
- [ ] Unreadable files produce explicit errors, never hangs.
- [ ] Manual paths persist across sessions.
- [ ] Parser/validator tests green.

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
- **`tail` read/follow** — verified against the GNU coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/tail-invocation.html`):
  - `-n num` outputs the last num lines (spec: 200/500/1k/5k).
  - `-f`/`--follow=how`: **default is `--follow=descriptor`** — "If
    you'd like to continue to track the end of a growing file even after
    it has been unlinked, use `--follow=descriptor`. This is the default
    behavior" — this is exactly the rotation behavior spec §10 relies on
    ("follow keeps the open fd"). `--follow=name` + `--retry` (`-F`)
    is the rotation-following alternative (we re-scan instead, and note
    the inode change).
  - Truncation: "if the tracked file is determined to have shrunk, tail
    prints a message saying the file has been truncated and resumes
    tracking from the start" — our `truncated: true` re-read handles
    the same race from the client side.
  - inotify-based follow is prompt; without inotify tail polls every
    1 s (`--sleep-interval`), which bounds our follow latency.
- **Clear** — GNU `truncate` can set a file to zero, but a pathname-only
  command cannot bind the confirmation preview to the object later opened.
  The target therefore uses the vendored libssh2 SFTP handle APIs described in
  spec 05: `lstat`, open without truncation, `fstat`, compare available
  attributes, and set the size on that handle. SFTP v3 has no inode/device
  field, so §5 states the remaining race limit instead of claiming a stable
  file identity.
- **PM2 log paths** — `pm2 jlist` JSON includes per-process log file
  paths (`pm_out_log_path`/`pm_err_log_path`); PM2 docs
  (`https://pm2.keymetrics.io/docs/usage/process-management/`, spec 03
  §13) confirm jlist as the machine interface.
- **Readability probe** — `test -r <path>` is POSIX sh's documented
  readability check (`test(1)`, `-r` flag); run batched via exec.
- **Download chunking** — bridge payload limit enforced at SDK
  `bridge/root.zig` L144 (`payload_too_large`); 64 KB base64 chunks
  (≈87 KB) stay well under the 1 MB budget (see spec 05 §13).

Sources: GNU findutils find(1), GNU coreutils manual (tail, truncate),
PM2 docs, SDK bridge/root.zig.
