# Spec 12 — Remote Desktop (VNC over SSH)

**Status:** 📋 (research complete) · **Depends on:** 02 (session worker), new `src/ws.zig` · **Spec owner:** core

## 1. Overview

A GUI console for any server that runs a VNC server — tunneled through
the SSH session we already own, rendered by noVNC in a per-server tab.
Agentless: the remote VNC server already exists (x11vnc, TigerVNC, a
desktop's built-in sharing). One-click setup helper can install one,
approval-gated.

## 2. Goals / non-goals

**Goals**
- Connect to a remote VNC server over an SSH direct-tcpip tunnel: `ws://127.0.0.1:<port>/<token>` → Zig RFC 6455 WebSocket server → SSH channel → remote TCP.
- Display picker (`:0`, `:1`, custom port), password from Keychain (`vnc:<server_id>`), fit-window scaling, clipboard, Ctrl+Alt+Del menu.
- Setup helper: probe for x11vnc/TigerVNC/listening ports; suggest install+start command in an approval card.
- Reuse the tunnel machinery for future DB tunnels.

**Non-goals**
- No VNC *server* implementation, no SSH X11 forwarding, no RDP, no
  audio, no clipboard file-transfer (v1), no multi-monitor layout mapping (v1).

## 3. User stories

- My VPS has a desktop environment; I open the Remote tab, pick `:1`, enter the VNC password once (stored), and get a working GUI.
- No VNC installed → I click "Set up VNC" and approve the suggested x11vnc command; the tab reconnects.
- I resize the window; the desktop scales to fit.

## 4. UI/UX

### 4.1 Remote tab
- Toolbar: display/port selector (`:0` 5900 · `:1` 5901 · custom) · Connect/Disconnect · Scale (fit / 100%) · Ctrl+Alt+Del · clipboard paste button · status.
- Canvas fills the tab; click to focus keyboard; keyboard shortcuts pass through to the remote (browser chords like `⌘L` are intercepted by noVNC config).
- States: `idle` → `starting tunnel` → `connecting (ws)` → `auth (VNC password)` → `connected` / `failed(reason)`.
- VNC password prompt on `credentialsrequired` (once per session; "remember" stores in Keychain).
- Setup helper card (when probe finds nothing): suggested command block + Approve/Run + Cancel (exact same approval-card pattern as spec 11).

### 4.2 Fingerprint/trust
- Uses the session's existing host-key trust (spec 02) — no new trust surface.

## 5. Bridge API

### `oars.vnc.start` `{server_id, host?, port?}` → `{ok, ws_port, token}`
- Defaults: `host = "127.0.0.1"` (the server's own loopback — where x11vnc listens), `port = 5900 + display`.
- Worker opens `libssh2_channel_direct_tcpip_ex(session, host, port, "127.0.0.1", 0)` and binds a listener on `127.0.0.1:0`; returns the ephemeral port + random token (32 hex chars).
- Tunnel auto-destroys after 15 s if no WebSocket connection arrives; always destroyed on `stop`/disconnect.
### `oars.vnc.stop` `{server_id, ws_port}` → `{ok}`
### `oars.vnc.probe` `{server_id}` → `{ok, x11vnc: bool, tigervnc: bool, listening:[{port, process?}]}`
- Exec: `command -v x11vnc tigervncserver Xvnc; ss -tlnp 2>/dev/null | grep -E ':59[0-9][0-9]'`.
### `oars.vnc.setup` `{server_id, display?}` → approval-gated exec of the suggested install command (see §6); audit entry.
### `oars.vnc.poll` `{server_id, ws_port}` → `{ok, state: listening|connected|closed, bytes_up, bytes_down, error?}` (stats for the tab footer)

## 6. Zig core design

### `src/ws.zig` — minimal RFC 6455 server (~250 lines)
- Upgrade: read HTTP request head; validate method GET, `Upgrade: websocket`, `Sec-WebSocket-Key`; **validate `Origin`** against `zero://app` / `http://127.0.0.1:5173`; **validate URL path** `/vnc/<token>`; respond `101` with `Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
- Frames: parse client frames (FIN/opcode, mask flag + key, 7/16/64-bit lengths), unmask payload; server frames unmasked; opcodes: binary/text (→ bytes to channel), ping → pong, close → reply + teardown; fragmentation (continuation frames) reassembled.
- Codec is pure (encode/decode on slices) — unit-testable without sockets.

### Worker-loop tunnel support (in `sessions.zig`)
- New op: `tunnel_start {id, host, port}` → channel + listener; new per-session `tunnels[]`:
  `{id, listener, ws_sock, handshake_done, recv_buf, send_buf, ssh_channel, state}`
- Each run-loop iteration (10 ms): accept pending (up to 1); drive handshake; `read(ws_sock)` → parse frames → append to channel write buffer; `libssh2_channel_read` → wrap as binary frame → write ws_sock (EAGAIN-tolerant, buffered); ping/pong/close; cleanup on either side EOF.
- `ws_sock` is a plain TCP fd (std.Io.net.Stream) — reads non-blocking via the same loop discipline.

### Frontend
- `VncTab.tsx`: `new RFB(canvas, ws://127.0.0.1:<port>/vnc/<token>, {credentials: {password}, wsProtocols: ["binary"]})`; event wiring (`connect`, `disconnect`, `credentialsrequired`, `securityfailure`, `desktopname`, `clipboard`); scale via `rfb.setScale`; `rfb.sendCtrlAltDel()`; clipboard: `rfb.clipboardPasteFrom(text)` + `clipboard` event → write to system clipboard via `native-sdk.clipboard.writeText`.
- Password: prompt → `vault.set("vnc:" + server_id, pw)` when "remember" checked.

## 7. Data model

- VNC password in Keychain (`vnc:<server_id>`). Last-used display per server: localStorage (client-side only). No other persistence.

## 8. Security

- Listener binds 127.0.0.1 only; Origin + token validation (a hostile local webpage cannot ride the tunnel); 15 s idle timeout; tunnel dies with the session.
- VNC auth: noVNC handles the DES challenge with the supplied password; password never crosses the bridge (stays in the frontend → noVNC).
- Traffic encrypted end-to-end by SSH; loopback segment is localhost-only.
- Setup helper is approval-gated and audited (installing software on the server).

## 9. Performance

- WebSocket frames ≤ 64 KB; bridge is zero-copy-ish (single copy into frame buffer). Target: smooth 60 fps at 1080p with tight encoding; verify against a local VNC server; degradation path = lower scale (client-side) — no protocol changes needed.
- Stats (`bytes_up/down`) counters per tunnel for the footer.

## 10. Edge cases

- VNC server requires auth type noVNC can't do (e.g., Unix login) → `securityfailure` surfaced with the server's message.
- Remote VNC unreachable (channel open fails) → tunnel reports error; UI shows "no VNC server on <host>:<port> — try the setup helper".
- WebSocket never connects → 15 s auto-teardown; `poll` reports closed.
- Tab closed mid-session → `oars.vnc.stop`; session disconnect cleans all tunnels.
- noVNC focus/keyboard quirks in WKWebView → capture key events on the canvas; verify `⌘` chords don't reach the remote (config `noVNC keyboard intercept`).

## 11. Testing

- Unit: WS handshake (valid/invalid key, bad Origin, bad token path), frame codec round-trip (masked client frames, fragmentation, ping/pong), channel-bridge byte fidelity.
- Integration (container): run `x11vnc` inside the container; `oars.vnc.start` → connect with noVNC in a headless WebKit test (or `websocket` client in Zig tests) → assert framebuffer updates arrive (RFB handshake bytes observed).
- Manual: real desktop session, resize, clipboard, Ctrl+Alt+Del, disconnect mid-session.

## 12. Acceptance criteria

- [ ] VNC session renders and accepts input against a real x11vnc in the test container.
- [ ] WS server rejects bad Origin/token; idle tunnels self-destruct.
- [ ] VNC password flows from Keychain → noVNC, never via bridge.
- [ ] Setup helper installs x11vnc only after approval + audit.
- [ ] Codec/handshake unit tests green.
