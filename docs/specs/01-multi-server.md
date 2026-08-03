# Spec 01 — Multi-Server Management

**Status:** Partial (CRUD, Keychain flow, and session tabs exist; persistence
hardening and grouping are not yet implemented) · **Depends on:** — · **Spec owner:** core

## 1. Overview

The fleet is the app's home screen: every server the user manages, saved
once and found by name. A server is a saved connection profile; opening it
creates a session tab. Oars has no profile-sync service. Profile data leaves
the machine only through a user-directed export or an explicitly disclosed
feature request.

## 2. Goals / non-goals

**Goals**
- Save a server once (name, host, port, user, auth), edit or delete it later.
- See fleet health at a glance: per-server connection state.
- Open any server into its own tab; many tabs at once.
- Group servers into folders/tags; filter and search the fleet.
- Keep secrets (passwords, passphrases) out of the config file, in the Keychain.

**Non-goals**
- No cloud sync, no team sharing, no discovery/scanning of networks.
- No per-plan limits — unlimited servers.

## 3. User stories

- As a user, I add my 3 VPSs once and never retype an IP again.
- As a user, I see at a glance which servers are connected and which failed.
- As a user, I connect to two servers at once and switch tabs without losing either session.
- As a user, I organize 40 client servers into folders and find one by typing two letters.
- As a user, I store a server's password in the Keychain once; connects reuse it.

## 4. UI/UX

### 4.1 Layout
- Left sidebar (236px): brand header, server list, footer (count), `+ Add server` button.
- Main area: tab bar (one tab per open view) + content. Multiple views of one
  server can share its single SSH session under spec 02.
- Each server row: status dot · name · host (mono, truncated) · edit affordance on hover.
- Status dot vocabulary (app-wide): connecting = amber pulse, ready = blue, error = red, closed = faint gray.

### 4.2 Interactions
- Click row → open its primary tab or focus an existing one → start connecting.
  “New mirrored tab” from the row menu or `Mod+T` opens another view backed by
  the same session and independent poll cursors.
- `+ Add server` → modal form (spec below). Edit (✎) → same modal prefilled.
- Delete: from edit modal, secondary danger action, type-to-confirm not required for config delete (no server mutation), but confirm dialog required.
- `Cmd/Ctrl+F` or `/` in sidebar → filters list by name/host/group (client-side, instant).
- `⌘K` opens the global palette (spec 13) which includes "open server …" entries.

### 4.3 Add/Edit modal fields
| Field | Type | Notes |
|---|---|---|
| Name | text | required; unique-ish (warn on duplicate) |
| Host | text | IP or hostname |
| Port | number | default 22 |
| User | text | default root |
| Auth method | segmented | Password / SSH key |
| Password | password | only for password auth; blank = keep existing (edit) |
| Private key path | text + Browse… | `native-sdk.dialog.openFile` picker |
| Key passphrase | checkbox + password | stored in Keychain |
| Group | text w/ datalist | target behavior: suggest existing groups |
| Tags | token input | free-form, normalized and deduplicated |

### 4.4 States
- Empty fleet: dashboard with "Add your first server" CTA + one-line hints.
- Saving: button disabled with "Saving…"; on error, inline form error.
- Duplicate name: inline warning, not blocked.

## 5. Bridge API

### `oars.servers.list` → `{ok, servers: Server[]}`
### `oars.servers.save` `{id?, name, host, port, user, auth_method, key_path?, key_has_passphrase?, group?, tags?, via_server_id?}` → `{ok, server}`
- `id` omitted → generated (timestamp-hex). `created_at`/`updated_at` set server-side (ns).
- On edit, preserve `created_at`. Preserve the trusted host fingerprint when
  host and port do not change. Clear it when host or port changes so the next
  connection must verify the new endpoint.
- Validate `via_server_id` against existing server ids and reject self-links,
  missing references, chains deeper than three, and cycles as defined by spec
  18.
### `oars.servers.delete` `{id}` → `{ok}`
- Side effects: disconnect any live session for that server first.

### `Server` JSON shape (canonical)
```json
{"id":"16f3…","name":"prod-api-01","host":"192.168.1.10","port":22,"user":"root",
 "auth_method":"password","key_path":"","key_has_passphrase":false,
 "host_fingerprint":"SHA256:base64-no-padding…","group":"production/platform",
 "tags":["customer-facing","nodejs"],"via_server_id":null,
 "created_at":1754…,"updated_at":1754…}
```

## 6. Zig core design

- `src/servers.zig` — `Server` model (deep-copy + deinit), `Store` (JSON
  file in app data dir, `Loaded` struct keeps file buffer alive for
  zero-copy parse strings — see ROADMAP §3 decision 6).
- `src/sessions.zig` — `Manager` maps server_id → live `Session`; ensures
  one connection per server; `disconnect` joins the worker thread.
- Groups and tags (target): the frontend derives folder paths and tag filters
  from the canonical `group` and `tags` fields returned by
  `oars.servers.list`; there is no separate groups store in v1.

## 7. Data model & persistence

- `~/Library/Application Support/Oars/servers.json` (macOS; XDG equivalents on Linux).
- Never contains: passwords, passphrases, key material, AI keys.
- Keychain accounts: `<server_id>` (SSH password or key passphrase).

## 8. Security

- Bridge commands origin-gated (`zero://app`, `http://127.0.0.1:5173`).
- Secrets only ever flow: Keychain → frontend → per-connect bridge payload → session worker → freed after auth.
- Config file is created and replaced with owner read/write permissions (0600
  on POSIX systems). A permissive existing file is tightened after an explicit
  warning and before the next secret-adjacent metadata write.

## 9. Performance

- `servers.list` < 10 ms (small JSON file); sidebar renders without layout
  thrash for 500+ servers (virtualize if > 200 rows).

## 10. Edge cases

- Corrupt `servers.json` → do not replace it. Move it to a timestamped
  `servers.json.corrupt-*` file, show a recovery error, and start with an empty
  in-memory list. The current code only returns an empty list; quarantine and
  user-visible recovery remain implementation gaps.
- Hostname whitespace is trimmed on save. A trailing slash is rejected because
  it is not part of an SSH host name.
- Port outside 1–65535 is rejected. It is never clamped silently.
- Duplicate connect attempt → idempotent success with the live session status.
  The current bridge returns `ok:false` with "already connected" and the
  frontend catches that text; replacing this text-coupled path is an
  implementation gap.
- Server deleted while tabs are open → all of its tabs show "server removed"
  and the shared session is torn down.

## 11. Testing

- Unit: Store round-trip (save→load), corrupt-file fallback, id generation, deep-copy independence (mutating copy doesn't affect original).
- Bridge: dispatcher-level save/list/delete with permission-denied negative test (exists in `main.zig`).
- Manual: add → edit → delete flows; Keychain write/read on macOS.

## 12. Acceptance criteria

- [ ] Add, edit, delete, and list servers survive app restart.
- [ ] Passwords never appear in `servers.json`.
- [ ] Deleting a server disconnects its session and closes its tabs.
- [ ] Sidebar shows live status dots for all servers with sessions.
- [ ] `zig build test` passes with store/bridge coverage.
- [ ] Editing a profile preserves `created_at` and preserves or clears the
      host fingerprint according to the endpoint rule above.
- [ ] Stored and displayed host fingerprints match OpenSSH's
      `SHA256:<base64-without-padding>` form. Existing hex records migrate only
      after the same host key verifies.
- [ ] `servers.json` is written with owner-only permissions and a corrupt file
      is quarantined before the app continues.

## 13. Research & References

Every claim below was verified against the installed code (this repo and the
installed Native SDK) rather than assumed.

- **Store model & JSON persistence** — implemented in `src/servers.zig`:
  `Server` model at L27 (deep-copy `copy()` L45, `deinit()` L62), `Store`
  at L75, corruption-tolerant `loadParsed()` at L94 (treats malformed JSON
  as "start fresh"), `save()` at L119 (creates the data dir on demand),
  `upsert()`/`delete()` at L133/L149, `makeId()` (timestamp-hex ids) at
  L174. The `Loaded` struct (L83) keeps the raw file buffer alive because
  Zig 0.16 `std.json` parses strings with `.alloc_if_needed` (strings may
  point into the input buffer) — this design decision is required by the
  std.json semantics, not a style choice.
  Current gaps found in this review: `servers.save` rebuilds an edited record,
  so it resets `created_at` and clears `host_fingerprint`; malformed JSON is
  treated as empty but is not quarantined; and the store does not explicitly
  set owner-only file permissions.
- **Bridge protocol (invoke/response, no native→JS push)** — verified in
  the installed SDK at
  `node_modules/@native-sdk/cli/src/bridge/root.zig`: `Handler` with
  `invoke_fn` (L86), `Dispatcher.dispatch` (L142) rejects
  `payload_too_large` (L144), `invalid_request` (L148),
  `permission_denied` (L152), `unknown_command` (L156), wraps handler
  results via `writeSuccessResponse` (L163, L223) and failures via
  `writeErrorResponse` (L160–161, L237). Handlers must return **raw
  result JSON** — double-wrapping causes the alias bug documented in
  ROADMAP §3. Our dispatcher is wired in `src/bridge.zig` L17–27 and
  `src/main.zig` L96–115 (bridge + builtin policies + allowed origins).
- **Origin gating** — `src/main.zig` `security.navigation.allowed_origins`
  (`zero://app`, `http://127.0.0.1:5173`); the dispatcher-level
  permission-denied test exists in `src/main.zig` (test at L119–160,
  asserts `https://evil.example` is denied).
- **Keychain for secrets** — the SDK's builtin `native-sdk.credentials.*`
  bridge commands require the `credentials` permission in `app.zon` and a
  matching entry in the `builtin_policies` table in `src/main.zig`
  (verified in our `app.zon`; both sides are required — see ROADMAP §3).
- **Unlimited servers / no cloud** — product decision, not a technical
  claim; nothing external to cite.

Sources: `src/servers.zig`, `src/bridge.zig`, `src/main.zig`, `app.zon`;
SDK: `src/bridge/root.zig` (installed at
`~/.nvm/versions/node/v24.18.0/lib/node_modules/@native-sdk/cli`).
