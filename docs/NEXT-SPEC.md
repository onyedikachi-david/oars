# Next Spec Implementation Guide

## Target

Implement **Spec 08 — per-server SSH Management**. Treat
`docs/specs/08-ssh-management.md` as the product contract, then correct that
contract where the current source audit below proves it incomplete. The next
feature after this one is Spec 10 Backups.

Read these files before editing:

- `docs/specs/README.md`, especially the worker-thread, mutation, secret, and
  acceptance rules
- `docs/DESIGN.md`
- `docs/specs/08-ssh-management.md`
- `docs/specs/09-access.md` and `docs/NEXT-SPEC.md` from commit `16b4b9e` for
  the shared access-source and mutation contracts
- `src/sshkeys.zig`, `src/keygen.zig`, and `src/integration_keys.zig`
- the `oars.sshkeys.*` handlers in `src/bridge.zig`
- access scan and mutation operations in `src/access.zig`, `src/bridge.zig`,
  and `src/sessions.zig`; Spec 08 must reuse their effective OpenSSH source
  model instead of creating a second one
- `frontend/src/KeysTab.tsx`, `frontend/src/bridge.ts`,
  `frontend/src/types.ts`, `frontend/src/App.tsx`, and `frontend/src/index.css`
- `frontend/preview.html`; each state in this guide needs a deterministic
  fixture

## Verified baseline

Spec 08 is already substantial. `src/sshkeys.zig` parses and rewrites
`authorized_keys` without a shell. It preserves comments, empty lines, CRLF,
options, and malformed rows; validates the embedded SSH key type; computes the
OpenSSH SHA-256 fingerprint; and derives key size only for understood formats.
`src/keygen.zig` delegates Ed25519 private-key generation to the installed
OpenSSH `ssh-keygen`, drives non-empty passphrases through a private PTY, checks
mode 0600, refuses existing destinations, and rolls back a partial pair.

The bridge exposes list, add, revoke, rotate, local generate, role list/create/
delete, and server deploy-key generation. The Alpine integration test covers
add/connect/revoke, stale-line rejection, replacement, a forced read-only SFTP
account, rejected shell/forwarding/file mutations, role deletion, deploy-key
generation, and audit rows. `KeysTab` has typed inventory, role, generation,
revoke, and rotate dialogs. The preview has deterministic keys and roles.

The current status is still **Partial**, not complete. Update the Spec 08 status
before implementation starts. The checked acceptance boxes in the spec record
an earlier backend pass; they do not cover the release blockers below.

Current verification on 2026-08-13:

- Frontend Vitest: 10 files and 93 tests pass, but there is no focused
  `KeysTab` test.
- Frontend production build passes. It reports the existing large-chunk
  warning.
- The ChatGPT in-app browser opens `frontend/preview.html`, reaches the Keys
  tab with no console errors, and has no document-level overflow at
  1327 × 964. The visible screen still omits the selected account, exact key
  source, source health, role drift, and job progress.
- `zig build test` passes when local test sockets are allowed. The restricted
  sandbox run passed 234 of 236 tests, then blocked the two tests that open
  local sockets with `PERM`; the permitted rerun exited successfully. Treat
  that sandbox denial as an environment limit, not a product failure.

## Release-blocking gaps

### 1. Bridge handlers wait on remote work

The `oars.sshkeys.*` handlers call `Manager.execWait`, then create SFTP
outcomes and call `wait`. Role listing can run several serial execs. A Keys tab
load or mutation can therefore hold the bridge/UI thread for tens of seconds.

Move every SSH and SFTP step into the owning session worker. Bridge handlers
may validate and copy a bounded request, create a snapshot or job record, queue
work, and serialize locked local state. They must return without waiting on a
socket. Poll calls only observe state; they never advance the operation.

Local `ssh-keygen` can also wait for 30 seconds. Run it on a bounded local job
worker. Cancellation and every error path after `fork` must terminate and reap
the child before the job becomes terminal.

### 2. Read failures look like an empty file

`sshkeysRead` returns `null` for missing, denied, timeout, too-large, transport,
decode, and parse failures. `oars.sshkeys.list` then uses `""` and reports
`keys:[]`. Add can also treat an unreadable file as empty and replace its
meaning with a new one-line file.

Return typed source outcomes: `missing`, `readable`, `denied`, `timeout`,
`too_large`, `transport_error`, and `parse_error`. Only `missing` can produce a
safe create plan. Every other state blocks mutation and stays visible in the
screen.

### 3. The fixed path is not the effective SSH policy

The current code resolves only `<home>/.ssh/authorized_keys`. OpenSSH can use
multiple `AuthorizedKeysFile` paths, tokens, `Match` rules, dynamic key
commands, trusted user CAs, and principal sources. A connected account can
therefore have a different static source or additional access outside the file
shown by the tab.

Extract the effective-policy and static-source logic used by Spec 09 into a
shared deep module. For the selected account, evaluate `sshd -T -C` through the
available privilege path, expand documented tokens, read each static source,
and surface dynamic or certificate sources as warnings. If effective policy
cannot be evaluated, label the view partial and allow mutation only against an
exact, readable source that the user selects. Never call that source the
account's complete SSH access.

The per-server screen covers the connected login and Oars-managed role
accounts. It does not enumerate every account on the server; the fleet Security
workspace owns that full-account audit. State this scope in the UI and link to
the full scan.

### 4. Conflict checks do not protect the complete preview

Revoke and rotate validate a fingerprint plus one line hash. An unrelated edit
to the same file can be overwritten because the request has no whole-file
identity. The spec text mentions expected metadata, but its old payload omits
it.

Every snapshot source needs `file_sha256`, mode, owner when observable, and an
exact path. Add, revoke, rotate, and role-key mutations must submit
`snapshot_id`, `source_path`, `file_sha256`, and the target `line_hash` when a
line exists. Re-read and compare before writing. A mismatch is a conflict; the
job must not merge an unreviewed external edit.

The writer remains line-preserving and uses a sibling temporary file, fsync,
preserved ownership/mode, and atomic rename. If the server cannot provide the
required atomic replacement, fail safely.

### 5. Mutations are not idempotent jobs

Add appends the same fingerprint again. Repeating a bridge request can repeat
remote work. Revoke, direct rotate, role changes, and deploy-key generation do
not provide a durable per-item result to the UI.

Use a frontend-generated `operation_id` for every mutation. A repeated ID
returns the existing job. Deduplicate an added fingerprint within the exact
account and source; the same fingerprint can still be valid in a different
account or source. Keep bounded retained jobs with explicit expiry. Audit
admission once and the terminal remote result once.

### 6. Direct replacement can lock out the operator

The current per-server rotate removes the old key in the same file rewrite that
adds the replacement. Atomic file replacement prevents a torn file, but it
does not prove that the new private key works.

Rotate in two stages. First add the new public key while retaining the old key,
re-read the source, and report `waiting_for_verification`. Then verify with the
selected local private key through a fresh SSH authentication attempt, or
require an explicit external-verification confirmation that includes the new
fingerprint. Remove the old key only after that gate. Cancel or failure leaves
both keys and explains the recoverable state.

### 7. Read-only roles can fail open

`sshkeysRoleOptions` returns `null` when the marker is missing or unreadable.
The ordinary add path can then write an unrestricted key to the role account.
Role listing also treats a missing marker as an empty role set, and it calls
authorized-key comments `users`, although comments do not identify people.

A role-key mutation must resolve a verified role policy first. Missing,
corrupt, stale, or unreadable policy blocks the write. List the account's exact
key fingerprints and policy state; treat comments only as display text. Verify
that every Oars-managed read-only key has `restrict`, the expected forced
read-only SFTP command, no PTY, and no forwarding. Show `drifted` when remote
state differs.

Role creation currently requires root even though the spec also allows an
approved non-interactive sudo path. Use root or a capability-probed `sudo -n`
plan. Preview the exact privileged actions before approval. Quote all account
and path values with the shared shell-quote rules. If setup succeeds but marker
write or later verification fails, keep a partial job with repair or cleanup
actions; never report success from only `useradd` exit 0.

Role deletion leaves the home directory by design. The dialog and job result
must show that path and must state that files remain. Require the exact account
name as confirmation.

### 8. Local passphrase storage is not wired

The UI always calls generate with `remember_passphrase:false`. The backend can
return `keychain_account`, but the frontend never stores the secret. The
current form therefore offers no working remember choice.

Add an explicit `Store passphrase in Keychain` control. After successful key
generation, store the passphrase under `localkey:<fingerprint>` only when the
user selected it. If Keychain storage fails, keep the generated files, report
the partial result, and give the account name for a retry. Do not cache this
passphrase in the frontend secret map.

Register the generation payload as sensitive in all bridge inspection and
diagnostic paths. Never log, audit, retain, or echo the passphrase. Zero the
owned Zig request buffer before release. Audit the destination and fingerprint,
not the secret or full private-key content.

### 9. Deploy-key management supports only one hidden mutation

`Copy deploy key` creates `~/.ssh/oars_deploy` as a side effect and then copies
the public half. The UI gives no approval, no fingerprint preview, no existing
state, and no way to manage distinct repository deploy keys. GitHub deploy
keys are repository-scoped, so a single opaque server key is not a complete
workflow.

Use an explicit Deploy keys section. List Oars-managed keys by stable ID,
repository label, path, fingerprint, and creation state. Generate one unique
Ed25519 identity per repository label with a no-clobber path and an owner-only
remote manifest beside the connected account's SSH state. Return the public
key and GitHub setup steps only after generation succeeds. Deletion must warn
that Oars cannot remove a key already registered on GitHub and require the
fingerprint as confirmation.

No GitHub API integration is part of Spec 08.

### 10. The frontend does not expose the real safety model

`KeysTab` shows only the connected account's conventional file, combines all
options into one “restricted” count, and has no source path, source status,
account selector, role drift, job result, or conflict recovery. It cannot add a
key to a newly created role because the typed API drops the backend's optional
`user`. Deploy-key creation is hidden inside a copy button. There are no
focused component tests.

Replace the decorative summary with a compact operational header. Keep one
primary action, `Add key`; put local generation and deploy-key management in
clear secondary actions. Do not infer safety from the presence of any option.
Show the exact parsed options and a separate policy assessment.

## Product flow

SSH Management stays in the per-server **Keys** tab. It has one controller and
one selected account/source context.

1. **Loading.** Keep the last completed snapshot visible. Show the selected
   account and source as refreshing. Do not replace the whole tab with a
   spinner after the first load.
2. **Ready.** Header shows account, evaluated scope, source count, snapshot
   time, and coverage. The main table shows comment, fingerprint, type/bits,
   exact source, options/policy, and actions. A side rail contains managed roles
   and deploy identities.
3. **Partial.** Keep readable sources visible. An attention section lists each
   unreadable, dynamic, certificate, malformed, or drifted source. A partial
   view never says “no keys” for a source that was not read.
4. **Job active.** Keep the snapshot visible and show a compact step list with
   queued/running/waiting/done/conflict/error/canceled states. A terminal job
   offers Refresh. Polling does not cause the next mutation.
5. **Disconnected.** Keep the last snapshot labeled stale. Offer the existing
   connect flow. Do not turn connection failure into an empty inventory.

The account selector contains the connected login and verified Oars-managed
roles. The source selector appears when effective policy yields more than one
static file. Dynamic or certificate sources are visible but are not editable
in v1.

### Add key

Paste a public key or generate a local Ed25519 pair. Inspect and normalize the
key in Zig before confirmation. Show fingerprint, type, comment, target account,
exact source path, and any enforced role options. If the fingerprint already
exists in that exact source, return an idempotent result. Confirmation starts a
job; refresh only after it finishes.

### Revoke key

Show account, source, comment, and full fingerprint. State that existing SSH
sessions can remain open. Require the full fingerprint for a role key or when
the selected key is the connected account's last observed direct key. Submit
the frozen file and line hashes. A conflict returns to the refreshed preview;
it never retries against new contents automatically.

### Rotate key

Show old and new fingerprints together. Stage the new key, verify the rewritten
source, then pause. Prefer a fresh authentication check with a selected local
private key. If the user verified outside Oars, require the new fingerprint as
confirmation. Only the commit phase removes the old line. A partial result
keeps both keys.

### Managed roles

Create flow selects Standard SSH or Read-only SFTP, shows the exact account
name and privileged plan, and optionally installs the first public key in the
same job. Read-only means file listing and download through forced SFTP. It does
not mean a read-only shell. Role detail shows policy health, exact fingerprints,
home path, shell, and repair/delete actions.

### Deploy keys

Create flow asks for a repository label and optional comment, then generates a
unique server-side key. The result shows the fingerprint, public key, private
path, copy action, and concise GitHub steps. Oars never uploads the private key
or claims that the public key is registered on GitHub.

## Corrected bridge contract

Use strict TypeScript request and response types. No SSH-management `any`
remains in `KeysTab`, `bridge.ts`, or `types.ts`. Use string IDs consistently.

```text
oars.sshkeys.inspect
  {public_key, comment?}
  -> {ok, normalized_public_key, fingerprint, key_type, bits?, comment}

oars.sshkeys.snapshot
  {server_id, account:{kind:"connected"|"managed_role", name?}}
  -> {ok, snapshot_id}

oars.sshkeys.snapshotPoll
  {snapshot_id}
  -> {ok, state:"queued"|"running"|"done"|"partial"|"canceled",
      server_id, account, scope, created_at_ms, finished_at_ms?,
      coverage, capabilities, sources[], keys[], roles[], deploy_keys[],
      warnings[]}

oars.sshkeys.snapshotCancel
  {snapshot_id}
  -> {ok}

oars.sshkeys.add
  {operation_id, snapshot_id, source_path, file_sha256,
   public_key, comment?}
  -> {ok, job_id, fingerprint}

oars.sshkeys.revoke
  {operation_id, snapshot_id, source_path, file_sha256,
   fingerprint, line_hash, confirm_fingerprint?}
  -> {ok, job_id}

oars.sshkeys.rotate
  {operation_id, snapshot_id, source_path, file_sha256,
   old_fingerprint, line_hash, new_public_key}
  -> {ok, job_id, new_fingerprint}

oars.sshkeys.rotateCommit
  {job_id,
   verification:{kind:"local_private_key", path, passphrase?}|
                 {kind:"external_confirmation", confirm_fingerprint}}
  -> {ok}

oars.sshkeys.jobPoll
  {job_id}
  -> {ok, state:"queued"|"running"|"waiting_for_verification"|
                 "done"|"partial"|"canceled",
      steps:[{id,state,error?}], result?}

oars.sshkeys.jobCancel
  {job_id}
  -> {ok}

oars.sshkeys.localGenerate
  {operation_id, destination, comment?, passphrase?}
  -> {ok, job_id}

oars.sshkeys.roles.plan
  {server_id, name, kind:"standard_ssh"|"read_only_sftp",
   action:"create"|"repair"|"delete"}
  -> {ok, plan_id, expires_at_ms, account, home?, commands[], effects[]}

oars.sshkeys.roles.commit
  {operation_id, plan_id, public_key?}
  -> {ok, job_id}

oars.sshkeys.deployKeys.generate
  {operation_id, server_id, repository_label, comment?}
  -> {ok, job_id}

oars.sshkeys.deployKeys.delete
  {operation_id, server_id, deploy_key_id, confirm_fingerprint}
  -> {ok, job_id}
```

Each source contains `path`, `kind`, `status`, `file_sha256?`, `mode?`,
`owner?`, and `error?`. Each key contains `source_path`, `line_index`,
`line_hash`, parsed fields, and `policy_assessment`; malformed rows retain raw
text but have no mutation action. Role `key_fingerprints` replace the misleading
comment-based `users` field.

Clamp all user text and arrays at admission. Keep the 4 MiB key-file cap and
64 KiB line cap from `src/sshkeys.zig`. Use at most 32 retained snapshots, 64
retained jobs, and 64 deploy-key manifest entries per server. Active work is
never evicted. Expire unfinished records after 10 minutes idle and terminal
records after 30 minutes.

## Core implementation

### Shared policy and writer modules

Keep `src/sshkeys.zig` pure. Add whole-file hashing, exact duplicate detection,
and plan helpers there. Extract effective `sshd -T -C`, path-token expansion,
static-source classification, and typed source errors from the access bridge
code into a shared module such as `src/sshd_policy.zig`. Both Spec 08 and Spec
09 use that module.

Move remote key operations into explicit session operations and outcomes in
`src/sessions.zig`. A session worker owns all libssh2 calls. A coordinator can
sequence a job, but it must communicate through bounded outcomes and never hold
the access or SSH-key registry lock while waiting.

Use one atomic writer for Spec 08 and Spec 09. It validates the frozen source,
preserves lines, stages beside the destination, sets owner/mode, syncs, renames,
re-reads, and returns the new file hash. Do not leave the old synchronous
`sshkeysRead`, `sshkeysWrite`, or `sshkeysRewriteCore` as a second mutation path.

### Role policy

Store only Oars-managed role metadata in an owner-only, versioned remote
manifest. Write it atomically and quarantine corrupt data instead of treating
it as empty. Verify the live account, home, shell, key source, and forced policy
on every snapshot. An existing unowned account with the requested name is a
conflict. Repair is a separate approved plan.

The read-only role stays a forced read-only SFTP contract. Test the server's
actual SFTP subsystem and `-R` support before creating the account. Every key
installed for that role receives the exact restrictive options. A missing or
drifted policy blocks new key installation.

### Local generation

Keep OpenSSH as the private-key encoder. Extend `src/keygen.zig` with explicit
child cleanup: every timeout, cancellation, prompt failure, and verification
failure after spawn terminates and reaps the child. Clear passphrase buffers on
all exits. Verify both output files before no-clobber install, then report the
fingerprint and public key through the local job result.

### Deploy identities

Generate unique server-side Ed25519 pairs with no passphrase for unattended Git
use. Paths are derived from a random stable deploy-key ID, not raw repository
text. The remote manifest maps ID to label, public fingerprint, and paths. File
modes are 0600 for the private key and owner-readable for the public key. Never
touch `authorized_keys`.

## Frontend implementation

Refactor `KeysTab` into small typed state modules or hooks instead of expanding
one component with every flow. Keep one snapshot poller and one active-job
poller. Cancel timers on server/tab change and unmount. Do not start a second
controller from the Security workspace.

Use the established Oars primitives and `docs/DESIGN.md`:

- one obvious primary action
- four or fewer useful metrics; omit metrics when status text is clearer
- operational tables with no more than seven visible columns
- text and icon labels for every status; color is supplemental
- dialogs with title, one-sentence consequence, affected account/source, and
  primary/cancel actions
- responsive rows that stack without hiding fingerprints or destructive
  consequences

Add deterministic preview modes for populated, empty, partial source, malformed
row, role drift, rotate waiting, conflict, disconnected, and deploy-key result.
Use the **ChatGPT in-app browser MCP** to inspect `frontend/preview.html` at
desktop and narrow widths. Do not add Playwright dependencies, loaders, config,
scripts, or tests to the repository.

Add focused frontend tests for:

- snapshot polling and stale-snapshot preservation
- unreadable source versus genuinely empty source
- account/source selection
- key inspection and duplicate result
- add, revoke conflict, staged rotate, cancel, and refresh
- remembered-passphrase success and Keychain failure
- role plan/commit, drift, repair, and typed delete confirmation
- deploy-key generation and deletion warnings
- timer cleanup on server change and unmount

## Required verification

Implementation is complete only when all of these checks pass in the current
checkout:

1. `zig fmt` on every modified Zig file.
2. `zig build test` with leak checks. A sandbox-local socket denial must be
   rerun with permission before interpreting the result.
3. `scripts/integration-test.sh`, including the Spec 08 Alpine path.
4. `npm --prefix frontend test -- --run`.
5. `npm --prefix frontend run build`.
6. `frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit`.
7. ChatGPT in-app browser review of every Keys preview state at desktop and
   narrow widths: no uncaught console errors, clipped dialogs, hidden actions,
   document overflow, or status that relies only on color.
8. `git diff --check`.

The integration suite must prove:

- effective multiple static key sources are listed with exact paths
- missing is empty, while denied/timeout/too-large/transport are partial and
  block mutation
- add is idempotent for one exact source
- an unrelated external file edit causes a whole-file conflict
- staged rotation keeps the old key until verification and keeps both on
  cancel/failure
- revoke removes only the reviewed fingerprint line and a new connection with
  that key fails
- root and approved `sudo -n` role plans work; unavailable privilege changes
  nothing
- read-only role SFTP reads work while shell, PTY, forwarding, and every tested
  file mutation fail
- corrupt or missing role policy cannot produce an unrestricted role key
- local key generation covers empty and non-empty passphrases, no-clobber,
  cancellation, timeout child cleanup, mode 0600, OpenSSH readability, and
  passphrase absence from argv, environment, response, audit, history, and logs
- two repository labels produce distinct deploy identities; deletion removes
  only the selected pair and never changes `authorized_keys`
- every admitted mutation and terminal result is audited once

## Definition of done

Mark Spec 08 complete only when the corrected contract, implementation, tests,
preview fixtures, browser inspection, and status table agree. If any required
runtime evidence is unavailable, leave the status Partial and name the exact
missing check. Then replace this guide with the implementation guide for
**Spec 10 — Backups**.
