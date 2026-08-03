# Spec 02 — Terminal (SSH)

**Status:** Partial (shell, exec, trust, single-reader polling, and Keychain
auth exist; independent poll cursors, PTY resize, and bounded cancellation are
not yet implemented) · **Depends on:** 01 · **Spec owner:** core

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
- I can open the same server in more than one tab and each tab mirrors the same
  session without stealing output from the other tabs.
- I reconnect after a network blip without restarting the app.

## 4. UI/UX

### 4.1 Terminal tab layout
- Header: server name · `user@host:port` (mono) · status (dot + label) · Connect/Disconnect button.
- Body: xterm.js canvas (dark ANSI theme; spec 16).
- Status labels: Connecting… / Verify host key / Authenticating… / Connected / Disconnected / Error (+message).

### 4.2 Host-key trust dialog
- First connect to a server → modal: "Verify host key", key algorithm and exact
  OpenSSH-style `SHA256:<base64-without-padding>` fingerprint, explanation,
  copy button, Reject, and Accept.
- Changed key → connection fails with the old and new fingerprints. Re-trust
  is a separate high-friction action that explains the interception risk and
  requires the user to verify and type the server name. Editing a profile does
  not silently clear a mismatch.
- Fingerprint stored in server config; future connects compare silently.

### 4.3 Keyboard & clipboard
- Terminal focused on tab open and on click.
- `Cmd+C`/`Cmd+V` with selection → local clipboard (xterm handles); plain terminal paste via `Cmd+V` when no selection.
- `Cmd+Shift+K` clears the terminal viewport on macOS. `Cmd+K` remains the
  global palette shortcut. Clearing is client-side; it does not change the
  remote shell or the worker buffer.
- Output-buffer overflow → amber toast "output buffer overflowed — some lines were dropped" (auto-dismiss 4s).

### 4.4 Exec UI (target)
- `oars.ssh.exec` results render in a small output pane (non-interactive): header with command + exit code, mono body, "copy" button. Used by scripts (06), monitor probes, logs follow.

## 5. Bridge API

### `oars.ssh.connect` `{server_id, password?, passphrase?}` → `{ok}`
- Starts a worker thread; connection proceeds asynchronously. The target API is
  idempotent and returns the existing session status when a connection already
  exists. The current handler instead returns a user-facing error and the
  frontend special-cases its text; this remains a compatibility gap.

### `oars.ssh.disconnect` `{server_id}` → `{ok}`

The current handler joins the worker synchronously. It has no proven 100 ms
bound because DNS and TCP connect are not cancellation-aware. Before this API
is complete, disconnect must request stop and keep the UI responsive while
worker cleanup finishes.

### `oars.ssh.poll` `{server_id, cursors?, rewind?}` → poll result
```json
{"ok":true,"status":"ready","error":"","trust":{"pending":true,"fingerprint":"SHA256:…"},
 "channels":[
   {"id":0,"kind":"shell","command":"","cursor":1200,"dropped":0,"pending":96,"eof":false,"exit":null,"data":"…delta…"}
 ]}
```
- Each tab keeps the last returned absolute `cursor` for each channel and sends
  those values in `cursors` on its next poll. The core does not advance a
  session-wide read cursor.
- `data` contains bytes after the requesting tab's cursor. `rewind:true` ignores
  supplied cursors and replays each retained channel from its buffer start for
  a fresh or explicitly rewound tab.
- If a requested cursor precedes the retained buffer, polling starts at the
  buffer start and reports the number of bytes missed in `dropped` for that
  response.
- Poll cadence: 80 ms. Budget: 384 KB data / poll, 256 KB / channel.

### `oars.ssh.input` `{server_id, data}` → `{ok}` (shell stdin)
### `oars.ssh.exec` `{server_id, command}` → `{ok, channel}` (channel id carries output)
### `oars.ssh.resize` `{server_id, cols, rows}` → `{ok}`
- Current gap: `Channel.resizePty` in `src/ssh.zig` is a no-op. The handler must
  call `libssh2_channel_request_pty_size_ex` and report failure before resize is
  considered implemented.
### `oars.ssh.trust` `{server_id, accept}` → `{ok}`

## 6. Zig core design

### 6.1 Session state machine (worker thread)
```
connecting → needs_trust → authenticating → ready → closed
                 │ (reject)                    │
                 └─────────→ closed            └→ error (connection lost / auth failed)
```
- `connecting`: resolve + TCP connect + libssh2 handshake. The handshake has a
  15 s deadline today. DNS and TCP connect still use blocking OS calls, so the
  full connection does not yet have a proven deadline.
- `needs_trust`: pause; wait for `trust(accept)` (50 ms poll, stop-aware).
- `authenticating`: password or key-file auth, 20 s deadline; error text captured from libssh2.
- `ready`: open shell channel (PTY 120×32, TERM=xterm-256color, then re-resized by client).
- Run loop: drain stdin queue → write channel; process ops (exec/resize/close); read every channel; keepalive every 30 s; 10 ms sleep.

### 6.2 Channel model
- `ChannelEntry {id, kind (shell|exec), stream, raw, stdin_queue, eof_seen}`.
- Exec channels: no PTY; on EOF capture `exit_status`, keep stream alive until drained, then free.
- One worker thread owns all libssh2 calls for a session. Calls that use the
  same `LIBSSH2_SESSION` must be serialized, including retries after
  `LIBSSH2_ERROR_EAGAIN`; bridge handlers only touch spin-locked buffers.
  Process-wide `libssh2_init` runs once before worker threads start.

### 6.3 Streams (shared with main thread)
- `Stream {data: ArrayList(u8), start_abs, end_abs, eof, exit_status, max_bytes=4MB}`.
- The stream retains bytes by absolute position. Poll is a non-destructive read
  from the cursor supplied by that tab, so any number of tabs can read the same
  retained bytes independently.
- Overflow drops the oldest bytes and advances `start_abs`. A reader whose
  cursor is behind `start_abs` receives a per-response `dropped` count and
  continues from `start_abs`.
- This is the target stream model. The current `Stream.readAvailable` advances
  one shared cursor, so two current consumers would drain each other's deltas.
  Mirrored tabs are not complete until that field is replaced by caller-supplied
  cursors and the bridge tests in §11 pass.

## 7. Data model & persistence

- Nothing persisted per-session except the host-key fingerprint (server config).
- History recording is specified in spec 15 and is not yet implemented.

## 8. Security

- All traffic SSH-encrypted. Keys/passwords per spec 01 §8.
- Bridge payloads carry transient secrets only during connect.
- Keepalive prevents silent dead connections; errors surface as explicit status, never hangs.

## 9. Performance

- 80 ms polling gives at most 12.5 display updates per second and adds up to one
  poll interval after output reaches the retained buffer. Measure the complete
  keystroke-to-render path; the acceptance target is below 250 ms.
- Streams cap at 4 MB/session/channel; `tail -f` at high rates degrades to dropped-warning instead of memory growth.

## 10. Edge cases

- Server dead / DNS fails → explicit error status with message, connect button returns.
- Host key changed → hard error (see §4.2).
- Auth failure → message from libssh2 (e.g. "Permission denied (publickey,password)").
- Input during connecting → queued? No: input returns `not ready`; frontend buffers keystrokes until `ready` (xterm writes are held by the poll loop — frontend responsibility).
- Channel read error mid-session → status `error` "connection lost", cleanup.
- Window minimized → ResizeObserver still fires on restore; PTY resized then.
- Multiple tabs for the same server share one SSH session and its channels.
  Opening the second tab starts it at the retained buffer start. Each tab polls
  with its own channel cursors, so all open tabs receive the same retained and
  future output without consuming another tab's deltas.

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
- [ ] Resize changes the remote PTY size and is verified with `stty size`.
- [ ] Disconnect remains responsive while DNS, TCP connect, handshake, or auth
      is in progress.
- [ ] Duplicate connect is an idempotent success and does not depend on matching
      an error-message string in the frontend.
- [ ] Two tabs for the same server share one SSH session, replay retained output
      on the second tab, and then receive identical new output independently.
- [ ] A slow mirrored tab reports its own dropped-byte gap after buffer overflow
      without changing the output seen by another tab.
- [ ] All existing tests pass (`zig build test`).

## 13. Research & References

- **Current session state machine** — implemented in `src/sessions.zig`: `Status`
  enum L21 (connecting/needs_trust/authenticating/ready/closed/error),
  `ChannelKind` L41, `Stream` (cursor-delta buffer) L56–66 with `append`
  L80, `readAvailable` L99, `snapshot` L119, `ChannelEntry` L136,
  `Session` L165, `Manager` L221 with `connect` L253, `disconnect` L300
  (joins the worker thread), `input` L333, `exec` L343, `resize` L355.
  One worker thread per session owns all calls for that session. The libssh2
  project guidance is more precise than the previous blanket statement:
  `libssh2_init` uses global state and must not run concurrently, while only
  one thread at a time can use a given session and must retain ownership across
  `EAGAIN` retries. This design satisfies both constraints
  (`https://libssh2.org/libssh2_init.html` and the project thread-safety
  guidance in `https://libssh2.org/mail/libssh2-devel-archive-2019-02/0010.shtml`).
- **Host-key verification APIs** — verified in
  `third_party/libssh2/include/libssh2.h`: `libssh2_session_handshake`
  L672 (replaces deprecated `libssh2_session_startup`, L669),
  `libssh2_session_hostkey` L687, `libssh2_hostkey_hash` L684 with
  `LIBSSH2_HOSTKEY_HASH_SHA256` defined at L498–501. SHA-256 fingerprints
  are the modern default (OpenSSH shows `SHA256:…` fingerprints since
  6.8; `ssh-keygen -l` uses them by default — see ssh(1) VERIFYING HOST
  KEYS, `https://man.openbsd.org/ssh.1`, which also documents the
  `-E` flag to select the hash algorithm).
  **Correction:** the current Zig code hex-encodes the 32-byte hash, while
  OpenSSH displays base64 without padding after `SHA256:`. The target contract
  now requires the canonical form and a verified migration for saved hex
  values.
- **Bridge/stream protocol** — see spec 01 §13: dispatch wraps raw JSON
  (`bridge/root.zig` L142–163); the frontend polls because the SDK bridge
  is invoke/response only (no native→JS push). **Current gap:** the installed
  implementation advances `Stream.cursor` in `readAvailable`, which supports
  one reader only. The per-consumer cursor request in §5 is a product contract
  still to implement, not a statement about the current source.
- **PTY + TERM=xterm-256color + resize** — libssh2 request_pty_ex is
  invoked via `libssh2_channel_request_pty_ex` (libssh2.h L879+);
  terminal resize semantics (SIGWINCH, cols/rows) are the client-side
  contract of the SSH session protocol (RFC 4254 §6.2, "Requesting a
  Pseudo-Terminal"). xterm-256color is the conventional TERM for
  modern xterm.js rendering (frontend uses xterm.js 5.3.0 — see spec 16
  §13).
  **Correction:** PTY creation is implemented, but resize is not. The current
  `resizePty` body discards all arguments. The spec now marks this feature as
  partial and requires a live `stty size` check.
- **Keepalive** — SSH-level keepalive via channel ping/EOF checks is a
  client-side reliability feature; libssh2 offers
  `libssh2_keepalive_config`/`libssh2_keepalive_send` (libssh2.h) for
  the transport-level variant. Our 30 s loop-level keepalive is
  documented behavior in this spec, verified to compile in
  `src/sessions.zig`.
- **Poll cadence math** — 80 ms poll ⇒ ~12.5 Hz; the budget (384 KB per
  poll, 256 KB per channel, 4 MB stream cap) is enforced in
  `src/sessions.zig` `Stream.max_bytes` (L68).

Sources: `src/sessions.zig`, `src/ssh.zig`, `third_party/libssh2/include/libssh2.h`;
RFC 4254 (ssh connection protocol); https://man.openbsd.org/ssh.1.
