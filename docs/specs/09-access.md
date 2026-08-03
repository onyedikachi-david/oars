# Spec 09 — Access Management (fleet)

**Status:** 📋 · **Depends on:** 01, 02, 08 (parser) · **Spec owner:** core

## 1. Overview

The people map: scan every saved server (read-only), assemble who can log
in where and who has sudo, then act — onboard one key to many servers,
offboard someone from all of them in one confirmed action, rotate a leaked
key everywhere, export the audit.

## 2. Goals / non-goals

**Goals**
- Fleet scan → person × servers × sudo table.
- Drill into a person → exact logins per server.
- Offboard (type-to-confirm), onboard (per-server role), rotate.
- Audit export (person/server/sudo CSV or JSON).
- Flag unreachable servers as Sync Errors — never silently clean.

**Non-goals**
- No continuous monitoring (snapshot semantics + re-scan), no session
  revocation (open sessions survive), no Windows servers, no SSO directory.

## 3. User stories

- HR asks who can reach prod — I export the table in one click.
- A contractor leaves — I type their name, their key dies on 6 servers.
- A new hire joins — I paste one key, tick 5 servers, set roles per server.
- A key leaked — I rotate it everywhere; nobody loses access.

## 4. UI/UX

### 4.1 Access view (app-level, not per-server)
- Header: counts (People · Servers · Grants) + Last scanned + Re-scan + Export Audit + Add user.
- People table: identity (comment, normalized) · key type · servers reachable · sudo count (badge) · actions (Open, Remove from all servers).
- Person detail: per-server rows `login@host` + sudo flag + Revoke on this server.
- Sync errors: banner "1 Sync Error — legacy-box could not be read, skipped".
- **Offboard dialog:** "contractor will lose access to 6 servers, 4 with sudo. Type the name to confirm." → progress list per server (revoked/error).
- **Add user dialog:** paste public key · server checkboxes (groups selectable) · role per server (root / standard / read-only) · Grant access → progress.

### 4.2 Roles per server in onboard flow
- root → append to root's authorized_keys; standard → append to user's; read-only → create/use role user (spec 08) and install key. Role list comes from `oars.sshkeys.roles.list` per target server.

## 5. Bridge API

### `oars.access.scan` `{server_ids?}` → `{ok, scan_id}`
- If `server_ids` omitted → all saved servers. Runs per-server workers (read-only execs), aggregates into a scan result. Poll for completion.
### `oars.access.poll` `{scan_id}` → `{ok, state: scanning|done, people, servers, grants, sync_errors:[{server_id, reason}], people: Person[]}`
```json
{"identity":"hiren@macmini","key_type":"ssh-ed25519","fingerprint":"SHA256:…",
 "grants":[{"server_id":"s1","user":"root","sudo":true}]}
```
- Identity normalization: comment field lowercased, trailing `@host` kept; keys without comments grouped under "unnamed <fingerprint-prefix>".
- Sudo detection per grant: exec `sudo -n true` (non-interactive probe) + parse `id` groups; combined → `sudo: true|false|unknown` (unknown when probe fails — shown, never guessed).
### `oars.access.offboard` `{identity, server_ids?}` → `{ok, job_id}` + `oars.access.jobPoll` `{job_id}` → per-server results
- Removes every key line whose comment matches the identity (all servers or listed ones). Type-to-confirm is client-side; server-side action is idempotent.
### `oars.access.onboard` `{public_key, grants:[{server_id, user_role}]}` → `{ok, job_id}`
- Role resolution per server; appends the key (dedupe by fingerprint across the target server).
### `oars.access.rotate` `{identity, new_public_key}` → `{ok, job_id}` (replace matching lines)
### `oars.access.export` `{format: csv|json}` → `{ok, path}` (via save dialog; written client-side from the last scan — no server round trip)

## 6. Zig core design

- `src/access.zig` — scan coordinator (fan-out to per-server exec probes through each server's session worker; aggregate results in a scan record; poll-driven), identity/key matching (fingerprint-aware), job runner (per-server steps with per-server results, cancellable).
- Reuses `sshkeys.AuthorizedKeys` parser/writer (spec 08) — the writer is the only mutating path and it's atomic.
- Sudo probe: one exec per server `sudo -n true 2>&1; id -Gn` — cheap, no TTY, non-interactive (no password prompt risk).

## 7. Data model

- Scan results: in-memory (latest scan per app session); export written on demand. Nothing about the map is persisted to disk in v1 (privacy by default); note: cache option later.

## 8. Security

- Scans are strictly read-only (exec `cat authorized_keys`, `id`, `sudo -n true` — no writes).
- Mutations (offboard/onboard/rotate) are job-based, idempotent, approval-gated (type-to-confirm for offboard), and fully audited (spec 15).
- The people map is the most sensitive view in the app — it never leaves the machine; export goes where the user chooses.

## 9. Performance

- Scan N servers in parallel (per-server workers), ≤ 2 s per server typical; progress shown per server.
- Job poll returns deltas; large fleets windowed.

## 10. Edge cases

- Server unreachable → `sync_error` row; never treated as clean.
- Key without comment → grouped as unnamed with fingerprint prefix; offboard by fingerprint still works.
- Same key on multiple users (shared key) → grouped under first comment; rotate replaces everywhere.
- Identity matches keys with different types → all removed (that's the point of offboarding).
- User already has a role user (read-only) → role creation skipped, key appended.

## 11. Testing

- Unit: identity normalization, fingerprint matching, sudo probe parsing, export formatting.
- Integration (containers): 2 servers × 2 users → scan → offboard identity → verify authorized_keys on both; onboard with per-server roles; rotate; unreachable server flagged (stop container).
- Manual: type-to-confirm flow, export CSV opens in Numbers/Excel.

## 12. Acceptance criteria

- [ ] Scan builds an accurate people map incl. sudo detection.
- [ ] Offboard removes the identity from every target server (verified by re-scan).
- [ ] Onboard installs keys with per-server roles.
- [ ] Unreachable servers are flagged, never silent.
- [ ] Export produces correct CSV/JSON; all mutations audited.

## 13. Research & References

- **authorized_keys parsing** — see spec 08 §13: format, options
  grammar, and permission rules verified against OpenBSD `sshd(8)`
  (`https://man.openbsd.org/sshd.8`, AUTHORIZED_KEYS FILE FORMAT).
  The identity key is the comment field; keys without comments are
  grouped by fingerprint — consistent with sshd treating the comment
  as "not used for anything (but may be convenient…)" (a comment is
  not required, so unnamed keys are a real case, not a corner fantasy).
- **Sudo probe** — `sudo -n true` verified against sudo(8)
  (`https://man7.org/linux/man-pages/man8/sudo.8.html`): `-n`,
  `--non-interactive` — "Avoid prompting the user for input of any
  kind. If a password is required for the command to run, sudo will
  display an error message and exit." So exit 0 ⇒ passwordless sudo
  works right now; non-zero ⇒ cannot confirm (shown as `unknown`,
  never guessed). Note sudo's credential cache (5 min per terminal,
  sudoers default) means a cached credential could make the probe pass
  even when a password would otherwise be needed — the spec's
  `sudo: true|false|unknown` vocabulary with `unknown` on failure is
  the honest presentation of that ambiguity.
- **`id -Gn`** — GNU coreutils `id` with `-G` (supplementary groups,
  plus primary with `-n` name form) verified in the coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/id-invocation.html`).
  Group membership is a secondary signal; sudo result takes precedence.
- **Offboard/onboard/rotate mechanics** — all three are
  read-modify-write of `authorized_keys` via the atomic writer from
  spec 08 (temp + rename, 0600); idempotency is guaranteed by
  fingerprint-keyed matching (same key on two lines is removed once —
  the writer is line-preserving except matches).
- **CSV export** — RFC 4180 comma-separated values (fields with
  commas/quotes/newlines quoted) — cite RFC 4180
  (`https://www.rfc-editor.org/rfc/rfc4180`); JSON export is
  std.json-serialized.
- **Snapshot semantics** — scanning is by design point-in-time (per
  §2 non-goals); no continuous monitoring claim is made.

Sources: OpenBSD sshd(8), sudo(8) man7, GNU coreutils id(1), RFC 4180,
spec 08 §13.
