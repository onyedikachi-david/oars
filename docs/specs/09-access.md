# Spec 09 — Access Management (fleet)

**Status:** 📋 · **Depends on:** 01, 02, 08 (parser) · **Spec owner:** core

## 1. Overview

The people map scans authorized keys and shows who can log in where and with
which account. A local identity record maps a person to one or more exact key
fingerprints. Authorized-key comments can suggest labels, but they never define
identity or authorize a mutation. Coverage and sudo status stay `unknown` when
Oars cannot read the required files or sudo policy.

## 2. Goals / non-goals

**Goals**
- Fleet scan → people × fingerprints × login accounts × servers, with an
  explicit complete or partial coverage state and an Unassigned Keys section.
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
- Header: counts (People · Keys · Servers · Grants) + coverage + Last scanned +
  Re-scan + Export Audit + Add person.
- People table: identity · fingerprints · login accounts · servers reachable ·
  sudo status · coverage · actions. Unassigned fingerprints appear in a
  separate review section and can be attached to a person.
- Person detail: per-server rows `login@host` + sudo flag + Revoke on this server.
- Sync errors: banner "1 Sync Error — legacy-box could not be read, skipped".
- **Offboard dialog:** "contractor will lose access to 6 servers, 4 with sudo. Type the name to confirm." → progress list per server (revoked/error).
- **Add person dialog:** name · public key · server checkboxes (groups
  selectable) · target login or read-only/read-write role per server · Grant
  access → progress. Saving creates the identity-to-fingerprint mapping before
  the grant job starts.

### 4.2 Roles per server in onboard flow
- Root and standard targets append to that account's authorized-keys file.
  Read-only access creates or reuses the forced-command role from spec 08 and
  installs the key with its restrictive options.

## 5. Bridge API

### `oars.access.scan` `{server_ids?}` → `{ok, scan_id}`
- If `server_ids` omitted → all saved servers. Runs per-server workers (read-only execs), aggregates into a scan result. Poll for completion.
### `oars.access.poll` `{scan_id}` → `{ok, state: scanning|done, people: PersonAccess[], unassigned: KeyAccess[], servers, grants, coverage, sync_errors:[{server_id, account?, reason}]}`
```json
{"identity_id":"p1","name":"Hiren","fingerprints":["SHA256:…"],
 "grants":[{"fingerprint":"SHA256:…","server_id":"s1","user":"root",
             "sudo":true,"comment":"hiren@macmini"}]}
```
- Canonical grouping key is the key fingerprint. Comments remain exact display
  labels and can differ across servers. `PersonAccess` is produced by joining
  scanned fingerprints with the explicit local identity registry. Never delete
  or rotate by comment.
- Default scan covers the connected login account only. Full-account scan
  enumerates local accounts and reads each `authorized_keys` file only when the
  session is root or has approved non-interactive sudo. The result includes
  `coverage: complete|partial` plus per-account errors.
- Read the effective `AuthorizedKeysFile` locations when authority and server
  tooling permit it. If Oars can only inspect the conventional path, mark
  coverage partial instead of claiming a complete server inventory.
- `AuthorizedKeysCommand`, conditional `Match` rules, directory services, and
  other dynamic key sources can make a static file scan incomplete. Report
  those sources and keep coverage partial unless Oars can evaluate the
  effective sshd configuration for each account and inspect every resulting
  source.
- Sudo status for a target login comes from an authoritative sudo policy query
  such as `sudo -n -l -U <quoted-user>` run with enough authority. `id -Gn` is
  only context because group membership does not include all sudoers rules.
### `oars.access.identities.save` `{id?, name, fingerprints[]}` → `{ok, identity}`
- Fingerprints are exact decoded-key fingerprints. A fingerprint can belong to
  at most one person unless the user explicitly marks it as shared.
### `oars.access.offboard` `{identity_id, grants:[{fingerprint,server_id,user,expected_line_hash}]}` → `{ok, job_id}` + `oars.access.jobPoll` `{job_id}` → per-server results
- The confirmation preview resolves the identity to an exact fingerprint and
  grant snapshot. The writer removes only those matching lines. Comment matches
  never authorize deletion.
### `oars.access.onboard` `{identity_id, public_key, grants:[{server_id, user_role}]}` → `{ok, job_id}`
- Role resolution per server; appends the key (dedupe by fingerprint across the target server).
### `oars.access.rotate` `{identity_id, old_fingerprint, grants[], new_public_key}` → `{ok, job_id}`
### `oars.access.export` `{format: csv|json}` → `{ok, path}` (via save dialog; written client-side from the last scan — no server round trip)

## 6. Zig core design

- `src/access.zig` — identity registry, scan coordinator, fingerprint-keyed
  grant matching, and a job runner with per-server results. Each saved server
  needs a live session or an explicit connection attempt; unreachable and
  unauthorized accounts remain visible in coverage errors.
- Reuses `sshkeys.AuthorizedKeys` parser/writer (spec 08) — the writer is the only mutating path and it's atomic.
- Scan planning records the connected account, which account files were read,
  and why any account was skipped. Sudo policy checks are per login account and
  remain unknown when Oars lacks authority to query them.

## 7. Data model

- `<data>/access_identities.json`: user-confirmed identity names and
  fingerprint membership. It contains public-key fingerprints, not private
  keys. Scan results remain in memory and exports are written only on demand.

## 8. Security

- Scans are read-only. A privileged scan still needs approval because it reads
  other users' sensitive access files and sudo policy.
- Mutations (offboard/onboard/rotate) are job-based, idempotent, approval-gated (type-to-confirm for offboard), and fully audited (spec 15).
- The access map is sensitive. It stays local unless the user exports it to a
  chosen path.

## 9. Performance

- Scan N servers in parallel (per-server workers), ≤ 2 s per server typical; progress shown per server.
- Scan and job polls return current snapshots; large fleet tables are windowed.
  Polling one view does not consume results from another.

## 10. Edge cases

- Server unreachable → `sync_error` row; never treated as clean.
- Key without comment → unassigned fingerprint until the user maps it; exact
  fingerprint actions still work.
- Same key on multiple users → one fingerprint with multiple grants and all
  observed comment labels. No comment is selected as the canonical identity.
- One person with multiple keys → the offboard preview lists every fingerprint
  and grant; the user can remove all or select a subset.
- Read-only role already exists → validate its forced-command policy
  before appending the key.

## 11. Testing

- Unit: identity/fingerprint joins, shared-key rules, expected-line conflicts,
  coverage, sudo policy parsing, and export formatting.
- Integration: 2 servers × 2 users → partial and privileged scans → offboard a
  selected fingerprint grant set → verify authorized keys on both; onboard,
  rotate, and stop one server to verify the sync error.
- Manual: type-to-confirm flow, export CSV opens in Numbers/Excel.

## 12. Acceptance criteria

- [ ] Scan builds an accurate people/fingerprint/login/server map, separates
      unassigned keys, and states whether coverage is complete or partial.
- [ ] Offboard removes only the selected fingerprint grants and detects
      concurrent line changes.
- [ ] Onboard installs keys with per-server roles.
- [ ] Unreachable servers are flagged, never silent.
- [ ] Export produces correct CSV/JSON; all mutations audited.

## 13. Research & References

- **authorized_keys parsing** — see spec 08 §13: format, options
  grammar, and permission rules verified against OpenBSD `sshd(8)`
  (`https://man.openbsd.org/sshd.8`, AUTHORIZED_KEYS FILE FORMAT).
  OpenSSH says the comment is not used for authentication. **Correction:** the
  earlier spec used that comment as an identity and mutation key. The People
  feature remains, but it now uses explicit local identity records joined to
  decoded key fingerprints; comments are suggestions and display labels only.
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
  the honest presentation of that ambiguity. **Correction:** this probe only
  describes the connected account. It cannot prove sudo access for every user
  whose key Oars finds. The contract now uses a privileged per-user policy
  listing when available and returns `unknown` otherwise.
- **`id -Gn`** — GNU coreutils `id` with `-G` (supplementary groups,
  plus primary with `-n` name form) verified in the coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/id-invocation.html`).
  Group membership is context only; sudoers can grant or deny access without
  matching a conventional group.
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
