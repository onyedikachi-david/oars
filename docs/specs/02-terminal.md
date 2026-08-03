# Spec 02 — Terminal (SSH)

**Status:** ✅ core in (history + exec UI pending) · **Depends on:** 01 · **Spec owner:** core

## 1. Overview

A full interactive SSH terminal per server tab, plus fire-and-stream exec
channels for command output (used by every other feature). Session state
lives in Zig worker threads; the frontend polls cursor-deltas and streams
keystrokes back.

## 2. Goals / non-goals

**Goals**
- Interactive shell (PTY, xterm-256color) with resize, scrollback, copy/paste.
- Host-key trust on first connect with fingerprint verification.
- Exec channels: run any command, stream output, capture exit codes — without a PTY.
- Multiple channels per session (shell + concurrent execs).
- Connect/disconnect/reconnect without app restart.

**Non-goals**
- No terminal multiplexer (tmux) integration in v1 — the server's own tmux works via the shell.
- No local shell; no X11 forwarding.

## 3. User stories

- I open a server and get a working prompt in under a second after auth.
- I resize the window and the PTY follows.
- I type fast under load and my input isn't dropped or reordered.
- A background exec (e.g. `tail -f`) streams output without blocking the shell.
- I reconnect after a network blip without restarting the app.

## 4. UI/UX

### 4.1 Terminal tab layout
- Header: server name · `user@host:port` (mono) · status (dot + label) · Connect/Disconnect button.
- Body: xterm.js canvas (dark ANSI theme; spec 16).
- Status labels: Connecting… / Verify host key / Authenticating… / Connected / Disconnected / Error (+message).

### 4.2 Host-key trust dialog
- First connect to a server → modal: "Verify host key", SHA256 fingerprint in 4-char groups, explanation, Reject / Accept buttons.
- Changed key → connection fails with explicit message; user can edit the server and clear the fingerprint (re-trust).
- Fingerprint stored in server config; future connects compare silently.

### 4.3 Keyboard & clipboard
- Terminal focused on tab open and on click.
- `Cmd+C`/`Cmd+V` with selection → local clipboard (xterm handles); plain terminal paste via `Cmd+V` when no selection.
- `Cmd+K` clears terminal viewport (scrollback preserved in session? — scrollback lives in xterm; clearing is client-side).
- Output-buffer overflow → amber toast "output buffer overflowed — some lines were dropped" (auto-dismiss 4s).

### 4.4 Exec UI (pending)
- `oars.ssh.exec` results render in a small output pane (non-interactive): header with command + exit code, mono body, "copy" button. Used by scripts (06), monitor probes, logs follow.

## 5. Bridge API

### `oars.ssh.connect` `{server_id, password?, passphrase?}` → `{ok}`
- Starts worker thread; connection proceeds asynchronously (see §6 state machine). "already connected" is a no-op success.

### `oars.ssh.disconnect` `{server_id}` → `{ok}` (synchronous; joins worker, bounded ≤ ~100 ms)

### `oars.ssh.poll` `{server_id, rewind}` → poll result
```json
{"ok":true,"status":"ready","error":"","trust":{"pending":true,"fingerprint":"ab12…"},
 "channels":[
   {"id":0,"kind":"shell","command":"","cursor":1200,"dropped":0,"pending":96,"eof":false,"exit":null,"data":"…delta…"}
 ]}
```
- `data` = bytes since the client's last poll (cursor-delta); `dropped` > 0 → gap warning; `rewind:true` replays from buffer start (fresh tab).
- Poll cadence: 80 ms. Budget: 384 KB data / poll, 256 KB / channel.

### `oars.ssh.input` `{server_id, data}` → `{ok}` (shell stdin)
### `oars.ssh.exec` `{server_id, command}` → `{ok, channel}` (channel id carries output)
### `oars.ssh.resize` `{server_id, cols, rows}` → `{ok}`
### `oars.ssh.trust` `{server_id, accept}` → `{ok}`

## 6. Zig core design

### 6.1 Session state machine (worker thread)
```
connecting → needs_trust → authenticating → ready → closed
                 │ (reject)                    │
                 └─────────→ closed            └→ error (connection lost / auth failed)
```
- `connecting`: resolve + TCP connect + libssh2 handshake, non-blocking with 15 s deadline.
- `needs_trust`: pause; wait for `trust(accept)` (50 ms poll, stop-aware).
- `authenticating`: password or key-file auth, 20 s deadline; error text captured from libssh2.
- `ready`: open shell channel (PTY 120×32, TERM=xterm-256color, then re-resized by client).
- Run loop: drain stdin queue → write channel; process ops (exec/resize/close); read every channel; keepalive every 30 s; 10 ms sleep.

### 6.2 Channel model
- `ChannelEntry {id, kind (shell|exec), stream, raw, stdin_queue, eof_seen}`.
- Exec channels: no PTY; on EOF capture `exit_status`, keep stream alive until drained, then free.
- One worker thread owns all libssh2 calls for the session (libssh2 is not thread-safe); bridge handlers only touch spin-locked buffers.

### 6.3 Streams (shared with main thread)
- `Stream {data: ArrayList(u8), start_abs, cursor, dropped, eof, exit_status, max_bytes=4MB}`.
- Overflow drops oldest bytes, rewinds cursor, increments `dropped` (spec'd and tested — see sessions.zig tests).

## 7. Data model & persistence

- Nothing persisted per-session except the host-key fingerprint (server config).
- History recording (pending): spec 15.

## 8. Security

- All traffic SSH-encrypted. Keys/passwords per spec 01 §8.
- Bridge payloads carry transient secrets only during connect.
- Keepalive prevents silent dead connections; errors surface as explicit status, never hangs.

## 9. Performance

- 80 ms poll ⇒ ~12.5 Hz terminal updates; keystroke→echo round trip ≈ 160 ms worst case locally — acceptable TTY feel; revisit async long-poll only if measured > 250 ms.
- Streams cap at 4 MB/session/channel; `tail -f` at high rates degrades to dropped-warning instead of memory growth.

## 10. Edge cases

- Server dead / DNS fails → explicit error status with message, connect button returns.
- Host key changed → hard error (see §4.2).
- Auth failure → message from libssh2 (e.g. "Permission denied (publickey,password)").
- Input during connecting → queued? No: input returns `not ready`; frontend buffers keystrokes until `ready` (xterm writes are held by the poll loop — frontend responsibility).
- Channel read error mid-session → status `error` "connection lost", cleanup.
- Window minimized → ResizeObserver still fires on restore; PTY resized then.
- Multiple tabs same server → single session shared; second tab rewinds and mirrors (poll is per-tab; both get the same deltas; acceptable).

## 11. Testing

- Unit: Stream cursor/overflow (exists); status machine transitions via injected handlers where feasible.
- Integration (dockerized sshd): full connect → trust → password auth → shell echo round-trip → exec `echo hi` exit 0 → exec `exit 3` exit 3 → resize → disconnect. Script: `scripts/dev-sshd.sh`.
- Manual: typing latency, resize, overflow toast, reconnect.

## 12. Acceptance criteria

- [ ] Interactive shell works end-to-end against a live sshd (key + password auth).
- [ ] Host-key trust persists and detects changed keys.
- [ ] Exec channels return correct exit codes and stream output.
- [ ] Typing latency under load stays below 250 ms round trip.
- [ ] No hangs: dead server surfaces an error within 20 s.
- [ ] All existing tests pass (`zig build test`).
