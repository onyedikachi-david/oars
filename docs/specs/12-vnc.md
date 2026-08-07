# Spec 12 — Remote Desktop (VNC over SSH)

**Status:** ✅ v1 frontend + backend implemented · **Depends on:** 02 (session
worker), `src/ws.zig` · **Spec owner:** core + frontend

## 1. Overview

A GUI console for a server that runs a VNC server. Oars tunnels the connection
through the SSH session and renders it with noVNC in a per-server tab. The
remote server can provide x11vnc, TigerVNC, or built-in desktop sharing. An
approval-gated helper can install x11vnc and can also install and start an XFCE
desktop on a headless server.

## 2. Goals / non-goals

**Goals**
- Connect to a remote VNC server over an SSH direct-tcpip tunnel: `ws://127.0.0.1:<port>/<token>` → Zig RFC 6455 WebSocket server → SSH channel → remote TCP.
- Display picker (`:0`, `:1`, custom port), password from Keychain (`vnc:<server_id>`), fit-window scaling, clipboard, Ctrl+Alt+Del menu.
- Setup helper: probe x11vnc, TigerVNC, listening ports, installed desktop
  commands, and a usable desktop on the selected display. For XFCE, usable
  means the window manager, desktop surface, and panel are all present. Show
  the exact VNC-only or VNC+XFCE plan in an approval dialog.
- Reuse the tunnel machinery for future DB tunnels.

**Non-goals**
- No VNC *server* implementation, no SSH X11 forwarding, no RDP, no
  audio, no clipboard file-transfer (v1), no multi-monitor layout mapping (v1).
- No automatic desktop package installation. The user must select the desktop
  option and approve the exact command.

## 3. User stories

- My VPS has a desktop environment; I open the Remote tab, pick `:1`, enter the VNC password once (stored), and get a working GUI.
- No VNC installed → I click "Set up VNC" and approve the suggested x11vnc command; the tab reconnects.
- My Ubuntu VPS is headless → I click "Set up desktop", keep the XFCE option
  selected, review the package and start commands, and approve them. Oars waits
  for the XFCE window manager, desktop surface, and panel before it reports
  success.
- I resize the window; the desktop scales to fit.

## 4. UI/UX

### 4.1 Remote tab
- Toolbar: display/port selector (`:0` 5900 · `:1` 5901 · custom) · Connect/Disconnect · Scale (fit / 100%) · Ctrl+Alt+Del · clipboard paste button · status.
- The noVNC target element fills the tab; noVNC creates and owns its display
  canvas. Click focuses the remote. Oars keeps app-reserved shortcuts local and
  forwards the remaining keys. Fit scaling uses
  `rfb.scaleViewport = true`; 100% uses `false`. `resizeSession` is a separate
  opt-in because it asks the VNC server to change framebuffer size.
- States: `idle` → `starting tunnel` → `connecting (ws)` → `auth (VNC password)` → `connected` / `failed(reason)`.
- VNC password prompt on `credentialsrequired` (once per session; "remember" stores in Keychain).
- If the negotiated scheme is legacy VNC Authentication, explain that only the
  first eight password characters participate. Do not show that warning for a
  stronger negotiated scheme.
- The probe strip reports the VNC server, desktop state, and listening ports for
  the selected display. A missing or stopped desktop changes the setup action
  to **Set up desktop** or **Start desktop**.
- The strip states package presence and display readiness separately, for
  example `XFCE installed · display :1 running`. Selecting a display stores it
  immediately, so setup, restart, and reconnect use the same display.
- The setup dialog contains an explicit **Install or start XFCE desktop**
  checkbox. It shows the exact package command and a password-redacted secure
  start preview. Clearing the checkbox produces a VNC-only plan.
- The dialog explains that desktop processes run as the connected SSH account.
  Package installation still requires remote root access.

### 4.2 Fingerprint/trust
- Uses the session's existing host-key trust (spec 02) — no new trust surface.

## 5. Bridge API

### `oars.vnc.start` `{server_id, host?, port?}` → `{ok, tunnel_id, ws_port, token}`
- Defaults: `host = "127.0.0.1"` (the server's own loopback — where x11vnc listens), `port = 5900 + display`.
- Worker opens `libssh2_channel_direct_tcpip_ex(session, host, port,
  "127.0.0.1", 0)` and binds a listener on `127.0.0.1:0`; returns the
  ephemeral port, a random lifecycle id, and an independent 128-bit URL token
  from the OS cryptographic random source.
- Tunnel auto-destroys after 15 s if no WebSocket connection arrives; always destroyed on `stop`/disconnect.
### `oars.vnc.stop` `{server_id, tunnel_id}` → `{ok}`
### `oars.vnc.probe` `{server_id, display?}` → `{ok, x11vnc, tigervnc, desktop_installed, window_manager_running, desktop_surface_running, desktop_panel_running, desktop_running, desktop_name, setup_state, listening}`
- The probe checks `x11vnc`, `tigervncserver`, and `Xvnc`, then reads listening
  `59xx` ports.
- It checks known desktop commands for XFCE, GNOME, KDE Plasma, MATE, and LXQt.
  For XFCE setup readiness, it also requires `dbus-run-session` and `xprop`.
- The probe reads X11 properties on the selected display. It reports the
  window-manager property separately from visible `xfdesktop` and
  `xfce4-panel` client windows.
- The probe validates that `_NET_SUPPORTING_WM_CHECK` contains a window ID.
  It does not trust `xprop`'s exit status because `xprop` can return success
  while it reports that the property is not found.
- For an XFCE session, `desktop_running` is true only when all three components
  are present. A window manager on a black root window, an active Xvfb process,
  or a VNC listener does not count as a usable desktop.
- `setup_state` is `idle`, `installing`, `installed`, `ready`, or `failed`.
  It comes from owner-only state and PID files below
  `$HOME/.local/share/oars/vnc`. A stale `installing` state becomes `failed`
  when its process no longer exists.
### `oars.vnc.setup` `{server_id, display?, dry_run, password?, install_desktop?}` → `{ok, action, executed, plan, hint, desktop_action, desktop_name}`
- A dry run returns an exact `install`, `configure`, or `manual` plan and never
  accepts or returns a password. Unknown targets get manual guidance rather
  than a guessed command.
- `install_desktop` defaults to false in the bridge contract. The frontend sets
  it only from the visible checkbox. `desktop_action` is `none`, `install`,
  `start`, `running`, or `manual`.
- Debian and Ubuntu use `apt-get update && DEBIAN_FRONTEND=noninteractive
  apt-get install -y` with the needed subset of `x11vnc xvfb xfce4 dbus-x11
  x11-utils`. Alpine uses `apk add --no-cache` with the needed subset of
  `x11vnc xvfb xfce4 dbus xprop`.
- The OS-release parser accepts quoted `ID` values and Debian/Ubuntu values in
  `ID_LIKE`. Supported images do not fall into manual setup because their
  `/etc/os-release` file uses quotes.
- Package installation runs in a detached process with mode-0600 status, PID,
  and log files. A repeated setup attaches to the existing process instead of
  starting a second package manager. This lock is server-wide because packages
  are not display-specific. The bridge waits up to 30 minutes. If the app
  restarts or that wait expires, installation continues and the next probe
  reports its durable state on every display.
- Execution requires a VNC password. It writes the password through bounded
  command input to an owner-only auth file. It never puts the password in the
  command string, process arguments, output, or audit record.
- When desktop setup is selected, Oars starts XFCE on the selected display with
  `dbus-run-session -- startxfce4`. It stores the PID and log below
  `$HOME/.local/share/oars/vnc`. It waits up to 60 seconds for the window
  manager, `xfdesktop`, and `xfce4-panel`. If the window manager is already
  running but a shell component is missing, Oars starts the missing XFCE
  components in that window manager's D-Bus session. It starts x11vnc only
  after the full readiness check passes.
- x11vnc always uses `-localhost -rfbauth`. Package installation requires
  remote root access. The desktop and VNC processes run as the connected SSH
  account. The audit journal records only the display and approved actions.
### `oars.vnc.poll` `{server_id, tunnel_id}` → `{ok, state: listening|connected|closed, bytes_up, bytes_down, error?}` (stats for the tab footer)

## 6. Zig core design

### `src/ws.zig` — bounded RFC 6455 server
- Upgrade: read at most 16 KB of HTTP/1.1 request headers within the handshake
  timeout. Require `GET`, `Host`, `Upgrade: websocket`, a `Connection` value
  containing `Upgrade`, `Sec-WebSocket-Version: 13`, and a valid
  `Sec-WebSocket-Key` that decodes to 16 bytes. Header names and HTTP token
  values are case-insensitive. Accept the measured packaged origin
  `zero://app` and the configured development origin
  `http://127.0.0.1:5173`; reject every other `Origin`. Validate the
  unguessable URL path
  `/vnc/<token>`. Respond `101` with `Sec-WebSocket-Accept =
  base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`. Require the
  client to offer the `binary` subprotocol and select it in the response.
  Decline `permessage-deflate` and every other extension by omitting
  `Sec-WebSocket-Extensions`; the frame codec does not implement extension
  semantics, so all RSV bits must remain zero.
- Frames: parse client frames (FIN/opcode, mask flag + key, 7/16/64-bit
  lengths), unmask payload; server frames unmasked; binary data forwards to the
  SSH channel; ping gets pong; close gets close. Reject non-zero RSV bits,
  unmasked client frames, invalid opcodes, fragmented control frames, control
  payloads over 125 bytes, non-minimal length encodings, and 64-bit lengths
  whose high bit is set. Text data is not part of this VNC bridge and closes
  with unsupported-data status. Enforce an 8 MB frame/message limit and a 16 MB
  connection-buffer limit. Stream complete binary fragments when possible
  instead of requiring unbounded message reassembly.
- Codec is pure (encode/decode on slices) — unit-testable without sockets.

### Worker-loop tunnel support (in `sessions.zig`)
- New op: `tunnel_start {id, host, port}` → channel + listener; new per-session `tunnels[]`:
  `{id, listener, ws_sock, handshake_done, recv_buf, send_buf, ssh_channel, state}`
- Each run-loop iteration (10 ms): accept pending (up to 1); drive handshake; `read(ws_sock)` → parse frames → append to channel write buffer; `libssh2_channel_read` → wrap as binary frame → write ws_sock (EAGAIN-tolerant, buffered); ping/pong/close; cleanup on either side EOF.
- `ws_sock` is a plain TCP fd (std.Io.net.Stream) — reads non-blocking via the same loop discipline.

### Frontend
- `VncTab.tsx`: `new RFB(target,
  ws://127.0.0.1:<port>/vnc/<token>, {credentials: {password},
  wsProtocols: ["binary"]})`; the constructor starts the connection. Later
  credential prompts use `rfb.sendCredentials({password})`. Public controls are
  `disconnect()`, `sendCtrlAltDel()`, `clipboardPasteFrom(text)`, and the
  `scaleViewport`/`resizeSession` properties. There is no public `connect()`,
  `setScale()`, or writable `credentials` property in installed noVNC 1.7.0.
- Password: prompt → `vault.set("vnc:" + server_id, pw)` when "remember" checked.

## 7. Data model

- VNC password in Keychain (`vnc:<server_id>`). Last-used display per server: localStorage (client-side only). No other persistence.

## 8. Security

- Listener binds 127.0.0.1 only; Origin + token validation reduce local
  cross-site access; 15 s idle timeout; tunnel dies with the session. The
  packaged macOS WKWebView was measured directly on 2026-08-03: the document
  URL is `zero://app/index.html`, `location.origin` is `zero://app`, the page is
  a secure context, and its WebSocket request sends `Origin: zero://app`. The
  static policy source `connect-src 'self' ws://127.0.0.1:*` allowed that
  loopback handshake. The complete application CSP can add the HTTPS provider
  and loopback HTTP sources required by spec 11, but VNC requires only this
  measured loopback WebSocket source. Development uses the configured
  `http://127.0.0.1:5173` origin.
- VNC auth: noVNC handles the negotiated authentication scheme with the
  supplied password. A remembered password crosses the credential bridge once
  from Keychain into frontend memory, then goes to noVNC. It is never written
  to app configuration, logs, or tunnel messages outside the VNC protocol.
- Traffic is encrypted between Oars and the SSH server. The short remote
  loopback segment between sshd and the VNC server is local plaintext, and
  legacy VNC authentication remains weak. The setup helper binds VNC to remote
  loopback and always configures authentication.
- Setup helper is approval-gated and audited (installing software on the server).
- A desktop is an explicit setup choice. Probe results cannot trigger package
  installation or process start by themselves.

## 9. Performance

- WebSocket frames and buffered messages use the bounds in §6. Set a
  latency and frame-rate target only after tests with common VNC encodings,
  WKWebView, and a 100 ms network path. Do not promise 60 fps before measuring.
- Stats (`bytes_up/down`) counters per tunnel for the footer.

## 10. Edge cases

- VNC server requires auth type noVNC can't do (e.g., Unix login) → `securityfailure` surfaced with the server's message.
- Remote VNC unreachable (channel open fails) → tunnel reports error; UI shows "no VNC server on <host>:<port> — try the setup helper".
- X is running but no window manager accepts the selected display → show the
  desktop as stopped and offer the approval-gated XFCE path.
- The XFCE window manager is running but `xfdesktop` or `xfce4-panel` is absent
  → show the display as incomplete, name the missing components, and offer
  **Repair desktop**.
- XFCE does not publish all required X11 windows within the readiness deadline
  → fail setup and return the bounded end of the desktop log. Do not report a
  blank framebuffer as successful desktop setup.
- A different desktop is installed but stopped → report its name. Oars still
  offers its supported XFCE setup path and names XFCE in the approval dialog.
- App restart during package download → keep the selected display, report
  `setup_state=installing`, disable duplicate setup, and let the detached
  package process continue. A failed process exposes retry state and keeps its
  owner-only install log for diagnosis.
- WebSocket never connects → 15 s auto-teardown; `poll` reports closed.
- Tab closed mid-session → `oars.vnc.stop`; session disconnect cleans all tunnels.
- noVNC focus/keyboard behavior in WKWebView → verify app-reserved shortcuts
  and remote modifier keys in a packaged build. There is no generic "noVNC
  keyboard intercept" setting to cite.

## 11. Testing

- Unit: WS handshake (valid/invalid key, bad Origin, bad token path), frame codec round-trip (masked client frames, fragmentation, ping/pong), channel-bridge byte fidelity.
- Integration (container): verify the detached install state lifecycle across
  separate SSH exec channels. The fixture includes XFCE packages; let the setup
  path start Xvfb, XFCE, and `x11vnc`; assert the window manager, desktop, and
  panel are visible; run
  `oars.vnc.start`; complete RFB 3.8 and VNC authentication through the
  WebSocket tunnel; read a 1280x800 raw framebuffer with varied pixels before
  adding a test window; then move the remote pointer, type into xterm, and
  verify byte counters and teardown.
- Manual: real desktop session, resize, clipboard, Ctrl+Alt+Del, disconnect mid-session.

## 12. Acceptance criteria

- [x] A VNC session renders and accepts pointer and keyboard input against a
      real x11vnc in the test container. `integration_vnc` completes RFB 3.8
      authentication, verifies varied pixels in the full 1280x800 raw
      framebuffer, checks the remote pointer with `xdotool`, and checks text
      entered into a real xterm.
- [x] The implementation preserves the measured packaged contract:
      `Origin: zero://app`, the `binary` subprotocol, no negotiated extensions,
      and a CSP that permits only the required loopback WebSocket source. The
      WS server rejects bad Origin/token and idle tunnels self-destruct.
      *(Bad Origin/token rejection and the 15 s idle self-destruct are
      covered: `ws.zig` handshake unit tests + `sessions.zig` tombstone
      tests; the CSP half lands with the frontend.)*
- [x] A remembered VNC password crosses the credential bridge once into
      frontend memory and then reaches noVNC. It never enters config, logs,
      audit, telemetry, or the VNC tunnel outside protocol authentication.
      Preview calls redact the value, and rejected credentials are removed
      before the retry flow.
- [x] Setup helper installs, configures, and starts loopback-only x11vnc only
      after approval and audit. Password bytes travel through bounded command
      input and are cleared after use.
- [x] On a headless Debian/Ubuntu or Alpine target, an explicit approved setup
      installs, starts, or repairs XFCE, waits for its window manager, desktop,
      and panel on the selected display, and then exposes that display through
      loopback-only x11vnc.
- [x] The real container path rejects and repairs an incomplete XFCE session,
      then verifies the clean desktop framebuffer before pointer, keyboard,
      byte-counter, and teardown checks.
- [x] The real SSH fixture starts a detached package job, observes
      `installing`, releases it from another exec channel, observes `installed`,
      marks `ready`, and confirms that state through the display probe.
- [x] Codec/handshake unit tests green.

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
    1009/1011…). §10.4 mandates implementation limits on frame and message
    sizes; the contract uses 8 MB per frame/message and 16 MB per connection.
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
  - `sendCredentials(creds)` is the public method for credentials supplied
    after `credentialsrequired`. The constructor initiates connection; only
    `disconnect()` is public. Earlier roadmap text naming `connect()` and a
    writable `credentials` field was corrected.
  - Events: `connect` (L930), `disconnect` (L944),
    `credentialsrequired` (L1653, incl. the RSA-AES variant at L2005 —
    noVNC supports RSA-AES auth, not only legacy DES),
    `securityfailure` (L1630/2132), `desktopname` (L704),
    `clipboard` (L2346/2484).
  - `wsProtocols: ["binary"]` is passed to the WebSocket open (L555)
    as a subprotocol request. The bridge selects `binary` in the upgrade
    response so the negotiated protocol is explicit.
- **Packaged macOS WKWebView measurement (2026-08-03)** — built the real
  frontend with `npm run build`, launched the Native SDK application with
  `zig build run -Dautomation=true`, and connected it to a local handshake
  capture server:
  - Runtime values were `location.href = zero://app/index.html`,
    `location.origin = zero://app`, and `isSecureContext = true`.
  - The upgrade request sent `Origin: zero://app`,
    `Sec-WebSocket-Protocol: binary`,
    `Sec-WebSocket-Extensions: permessage-deflate`,
    `Sec-Fetch-Site: cross-site`, and `Sec-WebSocket-Version: 13`.
  - A second packaged run added the exact static policy source
    `connect-src 'self' ws://127.0.0.1:*`; the upgrade request reached the
    loopback server. This proves the required VNC connection source works in
    the packaged WebView. The server must select `binary` and must omit
    `Sec-WebSocket-Extensions` because the bridge does not implement
    per-message compression.
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
- **XFCE and distribution packages** — the official Xfce getting-started page
  documents `startxfce4` as the command that starts the session, panel, window
  manager, and desktop (`https://docs.xfce.org/xfce/getting-started`). Ubuntu
  Noble publishes the `xfce4` metapackage and `dbus-x11` package at
  `https://packages.ubuntu.com/noble/all/xfce4` and
  `https://packages.ubuntu.com/noble/dbus-x11`. Alpine v3.20 publishes `xfce4`
  and `dbus` at `https://pkgs.alpinelinux.org/package/v3.20/community/x86_64/xfce4`
  and `https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/dbus`.
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
