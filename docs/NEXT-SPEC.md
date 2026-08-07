# Next Spec Implementation Guide

## Target

Complete the frontend for [spec 12, Remote Desktop](specs/12-vnc.md). The
WebSocket codec, SSH tunnel, VNC bridge handlers, setup plans, and backend tests
already exist. The current `VncTab` is a diagnostic draft, not the product UI.

Read these files before editing:

- `docs/DESIGN.md`
- `docs/specs/12-vnc.md`
- `frontend/src/VncTab.tsx`
- `frontend/src/bridge.ts` and `frontend/src/types.ts`
- `src/bridge.zig`, starting at the spec 12 handlers
- `src/sessions.zig`, starting at the VNC tunnel state
- installed `@novnc/novnc` 1.7.0 source and types
- `frontend/preview.html`; extend it, never delete or replace it

## Current Checkout Truth

The backend provides these commands:

- `oars.vnc.start {server_id, host?, port?}` returns
  `{ok,tunnel_id,ws_port,token}`.
- `oars.vnc.poll {server_id,tunnel_id}` returns tunnel state, byte counts, and
  an error string.
- `oars.vnc.stop {server_id,tunnel_id}` is idempotent.
- `oars.vnc.probe {server_id}` reports installed servers and listening ports.
- `oars.vnc.setup {server_id,display?,dry_run}` returns the plan before it
  executes. Execution is approval-gated and audited.

The current frontend wrappers use `any` and omit required tunnel IDs. The tab
embeds an iframe, but the backend returns a raw WebSocket tunnel, not a noVNC
web page. Replace this draft with typed contracts and a real `RFB` instance.

Use only installed noVNC 1.7.0 APIs verified in the spec: the constructor starts
the connection, later credentials use `sendCredentials`, scaling uses the
`scaleViewport` property, and controls use `disconnect`, `sendCtrlAltDel`, and
`clipboardPasteFrom`. There is no public `connect`, `setScale`, or writable
`credentials` field.

## Implementation Order

1. Add strict VNC start, probe, setup, and poll types. Pass `host`, `port`,
   `display`, `dry_run`, and `tunnel_id` exactly as the Zig handlers require.
2. Build one explicit lifecycle state machine: idle, probing, starting tunnel,
   connecting, credentials required, connected, failed, and stopped.
3. Own one tunnel and one `RFB` instance. Stop the tunnel and disconnect RFB on
   Disconnect, server change, tab unmount, failed start, and stale async return.
4. Render noVNC into a full workspace target. Keep the remote canvas unframed
   inside the primary content area, with a compact operations toolbar above it.
5. Add display presets `:0` and `:1`, a validated custom port, fit and 100%
   scale modes, Ctrl+Alt+Del, clipboard paste, connection status, and byte
   counters.
6. Handle `credentialsrequired` with a focused password dialog. Read and write
   `vnc:<server_id>` through the existing Keychain-backed `vault` helper. Never
   persist the password in config, preview calls, logs, or status text.
7. Probe before setup. Show the dry-run plan in the established Oars approval
   modal, then execute only after explicit approval. Unknown OS plans stay
   manual and must never run a guessed command.
8. Extend the preview with deterministic probe, start, poll, stop, setup-plan,
   setup-failure, credentials, and disconnected states. Keep all existing
   terminal, monitor, and log fixtures working.

## Validation Gate

Do not mark spec 12 implemented until all of these pass:

- `zig build`
- `zig build test`
- `npm --prefix frontend test`
- `npm --prefix frontend run build`
- `git diff --check`
- Desktop checks at 1440 x 1000 in light and dark themes
- Mobile checks at 390 x 844 with no overlapping toolbar controls
- Real noVNC canvas is nonblank and accepts pointer and keyboard input through
  the container tunnel; verify canvas pixels, not only DOM presence
- Display presets and custom port reach the exact backend payload
- Remembered and one-time password flows, with no password in recorded calls
- Fit/100%, Ctrl+Alt+Del, clipboard, poll stats, Disconnect, failed tunnel,
  stale start, server switch, and unmount cleanup
- Setup dry run, approval, execution, manual guidance, and failure states
- No console errors, stale state, leaked tunnel, text overlap, or blank canvas

After validation, update `docs/specs/12-vnc.md`, `docs/specs/README.md`,
`docs/ROADMAP.md`, and `docs/HANDOVER.md` with only current checkout evidence.
