# Spec 04 — Log Management

**Status:** 📋 · **Depends on:** 02 (exec/follow) · **Spec owner:** core + frontend

## 1. Overview

"Find the log" is the job. Oars scans a server, groups every log file it
finds (with size + last-write stamps so the active one is obvious), and
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
   "size":472000,"last_write_sec":92,"readable":true},
  {"path":"/var/log/auth.log","group":"system","name":"auth.log",
   "size":1.2e6,"last_write_sec":58,"readable":false}
]}
```
- Scan implementation (exec, cached 60 s):
```
find /var/log -maxdepth 3 -type f -name '*.log' -printf '%p %s %T@\n' 2>/dev/null
```
plus PM2 log paths from `pm2 jlist`, plus user-added paths. Grouping:
`nginx|apache` → web; `pm2|out|err` under app dirs → runtime; syslog/auth/kern → system; else custom.
- Readability probe: `test -r <path>` per source (batched; only for top-level scan results).

### `oars.logs.read` `{server_id, path, lines}` → `{ok, path, lines: [...], truncated}`
- `tail -n <lines>` (lines ∈ {200,500,1000,5000}); file size cap 64 MB read.
- `truncated: true` when the file grew between read and render (re-read tail).

### `oars.logs.follow` `{server_id, path}` → `{ok, channel}`
- Exec `tail -n 100 -f <path>` on a channel; output streams via `oars.ssh.poll` (channel kind `log`); client stops by closing the channel (`oars.ssh.closeChannel` — new command, spec 02 §5 extension).
- Add `oars.ssh.closeChannel` `{server_id, channel}` to the bridge (worker: send EOF, close, free).

### `oars.logs.clear` `{server_id, path}` → `{ok}` — `truncate -s 0 <path>` (exec), confirm required client-side, audit entry.
### `oars.logs.download` `{server_id, path}` → `{ok, job}` 
- Streams the file over an exec channel (`cat <path>`) to the client; frontend gets `native-sdk.dialog.saveFile` path first, then chunks via `oars.logs.readChunk` cursor protocol (reuse Stream + a save-to-disk loop in the frontend using the File System Access API if available in WKWebView, else chunked bridge writes to a native file — **pending decision:** v1 = `oars.file.saveChunk` bridge command writing app-side to the chosen path).

### `oars.logs.addSource` `{server_id, path}` → `{ok}` — persists to `sources.json` per server.

## 6. Zig core design

- `src/logs.zig` — scan/group/parse logic (pure functions + fixtures), source store (`<data>/sources.json` keyed by server_id), follow-channel helper reusing the session worker's exec path.
- Download path (pending decision): chunked write via `oars.file.writeChunk {path, offset, base64}` — bounded payloads, appends with fsync at end.
- No new threads: everything rides the session worker (scan/read = short execs; follow = exec channel).

## 7. Data model

- Per-server added paths: `<data>/logs.json` `{server_id: [paths]}`.
- Nothing else persisted — logs live on the server, by design.

## 8. Security

- Read-only by default; Clear is the only mutating action (confirm + audit).
- Paths from user input are passed as single argv elements to exec (no shell interpolation of user strings) — build commands as argv arrays or `exec` with proper quoting; user paths validated (`/` prefix, no `..` escapes beyond allowance).

## 9. Performance

- Scan ≤ 2 s on typical servers; cached.
- Follow streaming rides the poll budget; high-volume logs degrade to `dropped` warnings (visible in the viewer).
- 5,000-line loads render as a single windowed pass (mono rows, virtualization if needed).

## 10. Edge cases

- File deleted while following → channel EOF; viewer shows "source disappeared".
- File rotated (`access.log` → `access.log.1`) → follow keeps the open fd; note in UI when inode changes (compare `stat` path at re-scan).
- Binary/garbage content → sniff first 256 bytes; offer "download instead of render".
- Unreadable → `readable:false` + reason; never a spinner.
- Huge single line → clamp line render length (64 KB) with "line truncated" marker.

## 11. Testing

- Unit: grouping rules, fixture parses, path validation.
- Integration: create logs in the sshd container (nginx-style + PM2-style), scan → read → follow → write more lines → verify stream; clear → verify truncated; unreadable file (chmod 000) → verify failure surface.
- Manual: 5k-line search, download, rotation behavior.

## 12. Acceptance criteria

- [ ] Scan groups real log layouts and stamps size/last-write correctly.
- [ ] Read/follow/search/clear/download all work against the test container.
- [ ] Unreadable files produce explicit errors, never hangs.
- [ ] Manual paths persist across sessions.
- [ ] Parser/validator tests green.
