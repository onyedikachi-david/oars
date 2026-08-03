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
- Canvas fills the tab; click to focus keyboard; keyboard shortcuts pass through to the remote (browser chords like `⌘L` are intercepted by noVNC config). Fit scaling = `rfb.scaleViewport = true`; 100% = `false` (resize-session behavior via `rfb.resizeSession`).
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
- `VncTab.tsx`: `new RFB(canvas, ws://127.0.0.1:<port>/vnc/<token>, {credentials: {password}, wsProtocols: ["binary"]})`; event wiring (`connect`, `disconnect`, `credentialsrequired`, `securityfailure`, `desktopname`, `clipboard`); scaling via the `scaleViewport`/`resizeSession` properties (**not** a `setScale` method — see §13); `rfb.sendCtrlAltDel()`; clipboard: `rfb.clipboardPasteFrom(text)` + `clipboard` event → write to system clipboard via `native-sdk.clipboard.writeText`.
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

## 13. Research & References

- **WebSocket protocol (RFC 6455)** — verified against the authoritative
  text (`https://www.rfc-editor.org/rfc/rfc6455.txt`):
  - Handshake: client sends HTTP Upgrade (GET, `Upgrade: websocket`,
    `Connection: Upgrade`, `Sec-WebSocket-Key` = base64 of a random
    16-byte nonce, `Sec-WebSocket-Version: 13`, optional `Origin`)
    §4.1; server responds `101` + `Sec-WebSocket-Accept` =
    base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) §4.2.2.
  - Server-side Origin validation is explicitly sanctioned: §4.2.2
    step 4 (origin) — "The server MAY use this information as part of a
    determination of whether to accept the incoming connection… it
    MUST return an appropriate HTTP error code (e.g. 403)"; §10.2
    "Origin Considerations" recommends exactly this for servers not
    meant for arbitrary pages — our `zero://app`/127.0.0.1:5173
    allow-list implements this.
  - Framing §5.2: FIN/RSV/opcode(4)/MASK(1)/payload-len 7|16|64 bits;
    opcodes 0x0 continuation, 0x1 text, 0x2 binary, 0x8 close, 0x9
    ping, 0xA pong. Client→server frames MUST be masked §5.1/§5.3
    (fresh unpredictable 4-byte key, XOR `i mod 4`; server MUST close
    on unmasked client frames, 1002). Server frames MUST NOT be
    masked. Control frames ≤ 125 bytes and MUST NOT be fragmented
    §5.5; ping MUST be answered with pong (echoing payload) §5.5.2/3;
    close handshake §5.5.1 + status codes §7.4 (1000/1001/1002/1003/
    1009/1011…). §10.4 mandates implementation limits on frame sizes
    — our 64 KB cap is compliant.
  - The 15 s idle teardown and token-path check follow §10.7
    ("incorrect path or origin… the endpoint MAY drop the TCP
    connection").
- **RFB protocol (VNC wire protocol)** — the maintained community
  specification is the rfbproto project (linked from tigervnc.org,
  `https://github.com/rfbproto/rfbproto`); the classic reference is
  RealVNC's "The RFB Protocol" (`https://www.realvnc.com/docs/rfbproto.pdf`).
  Version 3.8 handshake: server sends protocol version, security
  types; "VNC Authentication" (type 2) is DES-based
  challenge-response: server sends a 16-byte challenge, client
  encrypts it with DES-ECB using the password (padded/truncated to 8
  chars, key bytes reversed) and returns 16 bytes. noVNC implements
  this (verified in source below); VNC passwords are effectively 8
  characters (x11vnc man page: "due to the VNC protocol only the first
  8 characters of a password are used (DES key)") — the setup helper
  should tell users this.
- **noVNC 1.7.0** — verified against the installed source
  `frontend/node_modules/@novnc/novnc/core/rfb.js` (and package.json
  version 1.7.0):
  - Constructor options: `credentials` (L118), `wsProtocols` (L121).
  - Scaling: `scaleViewport` (getter/setter L345–347) and
    `resizeSession` (L359–361) are **properties, not methods** —
    **correction:** the spec's `rfb.setScale` does not exist in the
    noVNC API; use `rfb.scaleViewport = true/false` (+ `resizeSession`
    for session resizing).
  - Methods: `sendCtrlAltDel()` L439, `clipboardPasteFrom(text)` L500.
  - Events: `connect` (L930), `disconnect` (L944),
    `credentialsrequired` (L1653, incl. the RSA-AES variant at L2005 —
    noVNC supports RSA-AES auth, not only legacy DES),
    `securityfailure` (L1630/2132), `desktopname` (L704),
    `clipboard` (L2346/2484).
  - `wsProtocols: ["binary"]` is passed to the WebSocket open (L555)
    as a subprotocol request — our WS server should accept it
    (or ignore it, which RFC 6455 permits).
- **x11vnc 0.9.16** — verified against the man page
  (`https://manpages.ubuntu.com/manpages/noble/en/man1/x11vnc.1.html`):
  - Typical usage `x11vnc -display :0`; listens on 5900+display
    ("PORT=XXXX… usually 5900") — matches spec's display/port math.
  - VNC password auth via `-rfbauth file` (created with
    `-storepasswd pass file`) or `-passwdfile`; man page strongly
    recommends a password. Warning: the rfbauth file "is NOT
    encrypted, only obscured with a fixed key" — keep it 0600; the
    setup helper should generate it server-side with `x11vnc
    -storepasswd` and delete any intermediate plaintext.
  - `-localhost` restricts to loopback connections ("Basically the
    same as `-allow 127.0.0.1`") — the documented way to run behind an
    SSH tunnel (the man page itself shows `ssh -t -L
    5900:localhost:5900 far-host 'x11vnc -localhost -display :0'`),
    exactly our architecture: tunnel in via SSH, x11vnc only accepts
    loopback.
  - `-forever` keeps listening after disconnect; `-N`/`-rfbport` set
    the port; `-display :N` selects the display.
- **TigerVNC** — verified at `https://www.tigervnc.org/`: Xvnc (server),
  vncpasswd, vncsession, vncviewer man pages hosted there; TigerVNC is
  packaged by Fedora/RHEL/Arch/etc. The setup helper probes
  `command -v x11vnc tigervncserver Xvnc` (install via the distro
  package manager — `apt install x11vnc` / `tigervnc-standalone-server`
  are the Debian/Ubuntu package names, verifiable per distro at
  packages.debian.org).
- **Tunnel reuse** — `libssh2_channel_direct_tcpip_ex` verified in
  `third_party/libssh2/include/libssh2.h` L850–854 (see spec 18 §13).

Sources: RFC 6455 (rfc-editor.org), rfbproto/RFB spec, noVNC 1.7.0
source, x11vnc(1), tigervnc.org.
