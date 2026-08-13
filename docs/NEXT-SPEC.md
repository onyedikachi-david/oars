# Next Spec Implementation Guide

## Target

Implement **Spec 09 — Fleet Access Management**. Treat
`docs/specs/09-access.md` as the product contract, then correct that contract
where the current source audit and primary references below prove it wrong or
incomplete. Do not reduce the feature to the small `AccessTab` that exists at
commit `0e94d4c`.

Read these files before editing:

- `docs/specs/README.md`, especially the cursor, mutation, research, and
  worker-thread rules
- `docs/DESIGN.md`
- `docs/specs/09-access.md` and the parser/writer contract in
  `docs/specs/08-ssh-management.md`
- `docs/research/spec-09-current-state.md`
- `src/access.zig`, the `oars.access.*` handlers in `src/bridge.zig`, and the
  access operation paths in `src/sessions.zig`
- `src/sshkeys.zig` and the existing SSH-key/role helpers in `src/bridge.zig`
- `src/integration_access.zig` and the access dispatcher tests in `src/main.zig`
- `frontend/src/AccessTab.tsx`, `frontend/src/bridge.ts`,
  `frontend/src/types.ts`, `frontend/src/App.tsx`, and `frontend/src/index.css`
- `frontend/preview.html`; every new access state needs a deterministic fixture

The research note records sources and current-state evidence. This guide states
the required implementation.

## Verified baseline

The backend is substantial. `src/access.zig` has an identity store, scan and
job models, fingerprint joins, CSV/JSON formatting, and bounded in-memory
registries. The bridge registers scan, poll, identity CRUD, offboard, onboard,
rotate, job poll, and export commands. The existing Alpine integration suite
exercises connected/full scans, partial coverage, sync errors, key mutations,
roles, and audit rows. The focused pure suite is 9/9 at `0e94d4c`.

That backend is **partial**, not complete. The current frontend uses `any`, raw
buttons, inline styles, `window.confirm`, and `window.prompt`. It has no onboard
or rotation flow, no person detail, no unassigned-key assignment, no server
progress, and no mutation result polling. An offboard click creates a queued
job and then stops, so no remote key is removed. Identity save also sends the
wrong wire shape: the backend requires `{identity:{...}}`, while the frontend
sends the identity fields at the payload root. Export returns content, but the
frontend looks for a path and never writes a file.

The core also has hard correctness and security gaps:

1. `accessExec` calls `execWait` from `oars.access.poll`. A single poll loops
   over every server, and each phase can wait 10 seconds. This violates the
   rule that the bridge/UI thread never waits on the network.
2. A connected-account scan can report `coverage:"complete"` after inspecting
   only that account. The response does not say that completeness is limited
   to the connected-account scope, so the UI can overstate a security audit.
3. Full scan uses a fixed `uid >= 1000` filter, reads only
   `~/.ssh/authorized_keys`, and greps config files. It misses root when root is
   not the connected account, valid login accounts below UID 1000, a second
   `AuthorizedKeysFile`, included and conditional configuration, certificate
   authorities, and dynamic key/principal sources.
4. `IdentityStore.next_id` resets to 1 on every app start. A new identity can
   therefore duplicate an existing `id-1`. Its writer truncates the live JSON
   file instead of using the repo's temp-sync-rename pattern.
5. Scan/job capacity silently evicts the oldest pointer, including work a view
   can still poll. Requests have no target or item cap, no expiry, and no
   idempotency key. A registry append failure can also free a new scan before
   the handler serializes its ID.
6. An errored server is terminal for poll, but `lastFinishedScan` accepts only
   `server.done`. A useful partial snapshot with a sync error can therefore be
   impossible to export.
7. Poll serialization drops rows when its byte budget is exhausted but sends
   no page cursor or truncation field. Frontend windowing cannot recover data
   the backend omitted.
8. Rotation changes remote lines but does not add the new fingerprint to the
   local identity. The next scan can show the rotated key as unassigned.
9. Mutations target a conventional per-user file, not the exact static source
   path frozen by the scan. They have a line hash but no whole-file identity,
   so an unrelated concurrent edit can be overwritten.

Do not retain a planned or complete status after these facts are known. Mark
Spec 09 **Partial** while implementation is in progress. Mark it complete only
after the acceptance checks at the end of this guide pass.

## Research corrections that change the design

OpenSSH `sshd -T` is the effective-config interface. With `-C`, it applies the
`Match` rules for supplied connection parameters before it prints the result.
Reading `/etc/ssh/sshd_config*` with `grep` is not equivalent. Use a privileged
`sshd -T -C user=…,addr=…,laddr=…,lport=…` probe when available. If Oars cannot
evaluate the effective configuration for an account, that account is partial;
do not guess. See [OpenBSD sshd(8)](https://man.openbsd.org/sshd.8).

`AuthorizedKeysFile` can contain multiple whitespace-separated paths. Paths
can be absolute or relative to the user's home and can contain `%%`, `%h`,
`%U`, and `%u`. `AuthorizedKeysCommand` is an additional dynamic source.
`TrustedUserCAKeys` plus `AuthorizedPrincipalsFile` or
`AuthorizedPrincipalsCommand` can grant certificate-based access that a list
of raw key fingerprints cannot enumerate. Surface each source and keep overall
coverage partial when the people map cannot resolve it. See
[OpenBSD sshd_config(5)](https://man.openbsd.org/sshd_config) and
[OpenBSD sshd(8), authorized_keys format](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).

The OpenSSH comment is display text only. It does not participate in
authentication. Fingerprints remain the canonical identity join, and every
mutation remains bound to a decoded key fingerprint plus the scanned source
record. Do not identify, delete, or rotate a key by comment.

`getent passwd` enumerates the configured Name Service Switch database, and
enumeration itself can be unsupported. Do not assume `/etc/passwd` is the
complete account source and do not use UID 1000 as the login boundary. Include
accounts with a usable login shell, then apply effective SSH policy; an
unsupported or unreadable account source makes coverage partial. See
[getent(1)](https://man7.org/linux/man-pages/man1/getent.1.html) and
[nsswitch.conf(5)](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html).

CSV remains RFC 4180 with CRLF records, quoting for commas/quotes/line breaks,
and doubled embedded quotes. Because server-controlled comments and identity
names can begin with spreadsheet formula characters, make the spreadsheet CSV
formula-safe and state that transformation in the export dialog. JSON is the
exact, unmodified audit format. Microsoft documents that CSV columns are
interpreted on import and that formulas begin with `=`; see
[Microsoft CSV import](https://support.microsoft.com/en-us/excel/get-started/import-or-export-text-txt-or-csv-files),
[Microsoft formula rules](https://support.microsoft.com/en-US/Excel/get-started/overview-of-formulas-in-excel),
and [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180).

## Product flow

Access Management is one app-level Security workspace. Remove it from the
per-server tab strip. A server detail link can navigate to the fleet view with
that server preselected, but it must not mount a second scan or job controller.

The workspace has four stable states:

1. **No snapshot.** Explain connected-account and full-account scopes. Show the
   selected fleet, connection readiness, and a primary `Scan access` action.
2. **Scanning.** Keep the last completed snapshot visible. Add a compact
   per-server progress list with queued/running/done/partial/sync-error states
   and a Cancel action. Do not replace the whole page with a spinner.
3. **Snapshot.** Show People, distinct keys, completed/target servers, observed
   grants, scope, coverage, and scan time. A partial banner lists every missing
   server, account, or dynamic source. Never summarize partial as clean.
4. **Job active or complete.** Show one result per exact server/account/source
   item. Polling observes the job; it does not trigger the next mutation.
   Partial failure remains visible and offers a re-scan.

The target picker groups profiles by the existing server group field. Before a
fleet scan, offer `Connect missing servers` through the existing connection and
Keychain flow. Host-key trust and authentication errors remain per server. A
scan can proceed with ready sessions, but every unresolved target becomes a
sync error in that same snapshot.

Full-account scan reads other users' key files and sudo policy. Show the exact
server list and sensitive-read explanation in an Oars dialog. Require an
explicit checkbox before sending the approval. A connected-account scan needs
no privileged-read approval, but its scope label must remain visible in the
header, table, export, and person detail.

### Snapshot layout

- Header actions: Re-scan, Export audit, Add person.
- Four compact metrics: People, distinct fingerprints, targets completed, and
  observed grants. Put coverage and scope beside the scan timestamp, not in a
  fifth decorative card.
- People table: Person, keys, login accounts, servers, privilege, coverage, and
  actions. Record `account_is_root` separately. Report sudo policy as `none`,
  `limited`, `full`, or `unknown`; do not reduce policy to a guessed boolean.
  Never rely on shield color alone.
- Person detail: exact fingerprint, server, account, static source path,
  privilege, key comment, and line identity. A single-grant revoke is available
  here.
- Unassigned keys: one row per fingerprint, all observed grants and comments,
  and `Attach to person`. Comments are suggestions, never the selected identity.

### Mutation flows

**Offboard** freezes the selected completed scan, identity revision, exact
fingerprints, and exact observed grants. The dialog states how many grants and
privileged grants are selected. The user types the identity name. If scope or
coverage is partial, the action is named `Revoke observed grants`; Oars cannot
claim the person is offboarded everywhere. Send the typed name to the backend
and validate it there.

**Onboard** starts with name plus one normalized OpenSSH public key. Derive and
show its SHA-256 fingerprint in the Zig core before identity save. Then choose
an exact account or a read-only role for each target server. Deduplicate only
within the exact target account; the same fingerprint can intentionally grant
different accounts on one server. Create the identity binding before the job,
and keep a recoverable partial state if some grants fail.

**Rotate** selects one old fingerprint and every observed grant to replace,
then validates and previews the new key. Run it in two stages: add and verify
the new key on every target first, then remove the old key only from targets
where verification succeeded. Keep both fingerprints attached to the identity
on a partial scan or partial job. Remove the old binding only when a
complete-scope scan proves that every known old grant was selected and every
replacement succeeded. A re-scan is required before the UI says rotation is
complete.

Identity delete is not offboarding. The dialog must say that deleting a local
label does not remove remote access.

## Corrected bridge contract

Use string IDs consistently. Add strict shared TypeScript types for every
request and response. No access-specific `any` remains in `AccessTab`,
`bridge.ts`, or `types.ts`.

```text
oars.access.key.inspect
  {public_key}
  -> {ok, normalized_public_key, fingerprint, key_type, comment}

oars.access.identities.list
  {}
  -> {ok, identities[], recovery_error?}

oars.access.identities.save
  {identity:{id?, name, bindings:[{fingerprint,shared}], expected_revision?}}
  -> {ok, identity}

oars.access.identities.delete
  {id, expected_revision, confirm_name}
  -> {ok}

oars.access.scan
  {server_ids[], scope:"connected_accounts"|"all_login_accounts",
   approved_sensitive_read:boolean}
  -> {ok, scan_id:string}

oars.access.scanCancel
  {scan_id}
  -> {ok}

oars.access.poll
  {scan_id, people_offset?, unassigned_offset?, limit?}
  -> {ok, scan_id, state, scope, coverage, created_at_ms,
      finished_at_ms?, metrics, servers[], people_page,
      unassigned_page, sync_errors[], source_warnings[]}

oars.access.offboard
  {operation_id, scan_id, identity_id, identity_revision, confirm_name,
   grants:[{fingerprint,server_id,user,source_path,line_hash,file_sha256}]}
  -> {ok, job_id:string}

oars.access.onboard
  {operation_id, identity_id, identity_revision, public_key,
   grants:[{server_id,target:{kind:"account"|"read_only_role",name}}]}
  -> {ok, job_id:string, fingerprint}

oars.access.rotate
  {operation_id, scan_id, identity_id, identity_revision, old_fingerprint,
   new_public_key, grants:[{server_id,user,source_path,line_hash,file_sha256}]}
  -> {ok, job_id:string, new_fingerprint}

oars.access.jobPoll
  {job_id}
  -> {ok, state:"queued"|"running"|"done"|"partial"|"canceled",
      results:[{server_id,user,source_path,
                state:"queued"|"running"|"done"|"conflict"|"error"|"canceled",
                error?}]}

oars.access.jobCancel
  {job_id}
  -> {ok}

oars.access.export
  {scan_id, format:"csv"|"json", path}
  -> {ok, path, rows, formula_safe}
```

The frontend obtains `path` from `native-sdk.dialog.saveFile`. The core writes
the selected local file with temp + sync + rename and returns no fleet content
over the bridge. Export is bound to the explicit completed `scan_id`, including
partial snapshots with sync errors. CSV includes observed people grants,
unassigned grants, source warnings, and sync errors through an explicit
`row_type` column. JSON preserves the complete typed snapshot.

`people_page` and `unassigned_page` contain `offset`, `limit`, `total`, `rows`,
and `has_more`. Do not silently omit rows at a byte threshold. Clamp `limit` to
100. Keep the current 512 KiB response ceiling as a final safety bound.

Each mutating request has a frontend-generated `operation_id`. Repeating an ID
returns the existing job instead of creating a second one. Validate the frozen
scan, identity revision, typed confirmation, source path, line hash, and whole
file hash before admission. Audit admission once and each remote result once.

## Core implementation

### Worker ownership and registries

Remove `accessExec` and every SSH/SFTP wait from bridge handlers. Add access
operation/outcome variants to the owning session worker. A bridge call may
queue work, consume a ready outcome, update locked local state, and serialize a
snapshot. It may not wait for a remote socket.

One scan coordinator can have one in-flight operation per target server.
Session workers provide concurrency across servers without a thread per scan.
Use explicit state IDs and short registry locks; never keep a pointer after
unlock unless its lifetime is pinned.

Keep these v1 admission bounds and test them:

- 256 deduplicated targets per scan
- 8 active or retained scans, with active work never evicted
- 256 items per mutation job
- 32 active or retained jobs, with active work never evicted
- 10-minute idle expiry for an unfinished scan and 30-minute retention for a
  terminal scan/job

Reject at admission when a safe slot is unavailable. Cancel or disconnect
marks unfinished server/items explicitly. Poll is a snapshot and has no
side-effect beyond expiry cleanup.

### Identity store

Migrate `access_identities.json` to a versioned record with random IDs,
per-fingerprint shared flags, integer-millisecond timestamps, and a monotonic
revision. Detect duplicate IDs during load. Use sibling temp, file sync,
mode 0600, and atomic rename. Quarantine corruption and return the quarantine
path as `recovery_error`; never silently present a corrupt registry as an empty
one.

Save and delete use compare-and-swap revisions. A fingerprint belongs to one
identity unless that exact binding is marked shared. The UI must explain shared
bindings before it creates one.

### Scan facts

For each server, record the requested scope, connection status, connected
account, privilege path, enumerated accounts, effective SSH source policy,
every static source read, sudo/privilege result, and exact failure reason.

For full scope:

1. Capture the live connection tuple from `SSH_CONNECTION`.
2. Enumerate NSS accounts with `getent passwd`. Include root and all accounts
   with a usable login shell; do not use a fixed UID threshold. Record
   unsupported enumeration as partial.
3. For each account, run effective `sshd -T -C` through the approved privilege
   path and parse `pubkeyauthentication`, every `authorizedkeysfile`,
   `authorizedkeyscommand`, `trustedusercakeys`, and authorized-principal
   sources. If effective evaluation is unavailable, mark that account partial.
4. Expand only documented tokens in static key-file paths. Read every resolved
   static file. Distinguish `missing`, `denied`, `timeout`, `too_large`,
   `transport_error`, and `parse_error`; only `missing` is inspected-empty.
   Unsupported tokens, dynamic commands, certificate authorities, and
   unreadable sources are explicit partial reasons.
5. Preserve authorized-key options and classify direct keys separately from
   certificate-authority grants. Store each observed direct grant with its
   server, account, source path, decoded fingerprint, exact comment, options,
   line hash, and whole-file SHA-256. Never turn a CA line into a direct person
   grant.
6. Query target-account sudo policy only with enough authority and `LC_ALL=C`.
   Return `none`, `limited`, `full`, or `unknown`, and record root accounts
   separately. An arbitrary group name is context, not proof.

Connected-account scope evaluates only the connected login and says so in
every response. `coverage:"complete"` means complete **for that scope**.
Exports and UI must retain the scope label.

### Mutation jobs

Reuse the spec-08 parser, but bind every mutation to the exact static source
file found by the scan. Stage the rewritten file beside the destination,
preserve unrelated lines and authorized-key options, recheck the whole-file
hash immediately before rename, set the required owner/mode, then rename.
Return `conflict` when either the line or file identity changed. State clearly
that an external writer that ignores Oars' lock can still race after the last
check; never describe SFTP as a true remote compare-and-swap primitive.

Jobs start after the approved request is accepted. `jobPoll` only observes.
Cancel stops queued items; an already-running single-file operation completes
and reports its result. Disconnect makes the affected item an error and does
not convert it to success.

Rotation first adds and verifies the new key on every target. It removes the
old key only from targets that passed the first stage, then updates the identity
revision according to the complete/partial rule in the product flow. After
onboard, make sure the inspected fingerprint is bound to the selected identity
before remote mutation. Offboard does not delete the identity automatically.

## Frontend implementation

Rebuild `AccessTab` as a typed app-level workspace that uses the current Oars
surface, button, status, loading, and modal primitives. Reuse
`useModalFocus`; every dialog has `role="dialog"`, a labelled title and
description, initial focus, focus trap, Escape, and focus restore. Remove every
native prompt/confirm and inline style.

Keep the page calm: one bordered workspace surface inside the rounded app
shell, a compact metric row, one primary people table, and progressive detail.
Avoid nested card grids. Use the existing responsive gutter system. At narrow
widths, metrics wrap, table rows become labelled records, and dialogs fit the
viewport without horizontal scrolling.

Implement these dialogs and panels:

- scan scope/targets/privileged-read confirmation
- add or edit person, including public-key inspection and shared-binding review
- attach an unassigned fingerprint
- person detail and single-grant revoke
- offboard with exact typed name and partial-coverage warning
- onboard target/role matrix and per-item results
- rotate key preview and partial-result recovery
- identity delete with the local-only warning
- export format/path dialog with formula-safe CSV explanation

Retain timer IDs and generation tokens for scan/job polling. Cancel them on
unmount, scan replacement, and job replacement. Poll until a real terminal
state; never stop after a fixed attempt count and pretend the snapshot is done.
Surface transport errors and preserve the last good snapshot.

Extend `preview.html` with `access=empty`, `scanning`, `populated`, `partial`,
`offboard`, and `job-error`. Mock the final typed wire shapes, pagination,
dialog actions, and save-path cancellation. Add no fake backend state that the
real bridge cannot return.

## Required tests

### Pure and dispatcher

- identity migration, restart-safe IDs, duplicate-ID rejection, atomic save,
  recovery error, revision conflict, and per-binding sharing
- OpenSSH public-key inspection and canonical SHA-256 fingerprints
- NSS enumeration without a UID cutoff, nologin classification, and
  enumeration-unsupported coverage
- effective-sshd parsing with `Match`, multiple `AuthorizedKeysFile` paths,
  documented token expansion, dynamic keys, CA/principal sources, and partial
  reasons
- privilege parser for none/limited/full/unknown with `LC_ALL=C`, with root
  recorded as an account property
- people/unassigned joins, repeated keys across accounts, scope-aware coverage,
  distinct counts, pagination, and sync-error exports
- RFC 4180 output, formula-safe spreadsheet fields, exact JSON, and atomic
  chosen-path writes
- active registry admission, expiry, cancel, disconnect, operation-id
  idempotency, and partial jobs
- exact line/file conflict guards, unrelated-line preservation, role options,
  rotate identity update, and audit cardinality
- dispatcher payloads match the TypeScript contract; string IDs and
  millisecond timestamps round-trip exactly
- a poll with slow/unreachable workers returns promptly because it does not
  execute a network wait on the bridge thread

### Integration

Use two isolated instances of the existing Alpine SSH fixture, not an Ubuntu
image. Give each two login accounts, different static key-file layouts, and
different sudo policy. Cover connected scope, approved full scope, multiple
`AuthorizedKeysFile` paths, a dynamic/CA partial source, one unreachable
profile, offboard, onboard to an existing account and read-only role, rotate,
whole-file conflict, idempotent duplicate operation IDs, cancellation, export,
and audit rows. Verify the final authorized-key files and identity registry,
not only bridge status strings.

### Frontend and visual

- typed scan lifecycle, indefinite polling, replacement/unmount cleanup, and
  preservation of the last snapshot
- scope and partial-coverage labels cannot disappear in table/detail/export
- add/edit/attach, onboard, offboard, revoke, rotate, delete, and export flows
- type-to-confirm and privileged-read checkbox gates
- job progress and partial recovery; polling actually drives to terminal UI
- keyboard/focus behavior and no `window.prompt`/`window.confirm`
- empty, scanning, populated, partial, and error previews at desktop and narrow
  widths with no console errors or horizontal overflow

## Definition of done

- A full approved scan accurately inventories every resolvable static SSH key
  source on two independent servers and reports dynamic, certificate,
  unreadable, unconnected, and unsupported sources as partial.
- Connected-account scope is never presented or exported as a full-server
  audit.
- People and unassigned rows join only by decoded fingerprint. Comments remain
  display labels.
- Offboard/revoke, onboard, and rotate run after one approval, show every
  result, preserve unrelated key lines/options, detect stale files, and keep
  identity bindings correct after partial failure.
- No access handler waits on SSH/SFTP. Slow and unreachable servers do not
  freeze the window.
- CSV and JSON are written to the path selected by the user; partial coverage,
  sync errors, and unassigned grants are retained in the export.
- The Access UI is app-level, typed, keyboard-safe, responsive, and uses no
  browser-native prompt/confirm or raw unstyled buttons.
- Focused pure, dispatcher, two-server Alpine integration, frontend, TypeScript,
  build, preview, and `git diff --check` checks pass. Update Spec 09 status and
  acceptance boxes only after this evidence exists.
