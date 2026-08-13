# Spec 09 Access Management Research and Current-State Audit

**Reviewed:** 2026-08-12

**Checkout:** commit `0e94d4c`

**Scope:** `docs/specs/09-access.md`, the shared architecture and design
contracts, the access and SSH-key core, bridge handlers, frontend access view,
and the existing unit, dispatcher, and container integration coverage.

This note records evidence for the next implementation guide. Spec 09 remains
the planned product contract. Existing backend code does not reduce that
contract, and passing backend tests do not make the access-management feature
complete.

## Method

The audit used four evidence classes:

1. The product and design contracts in `docs/ROADMAP.md`,
   `docs/specs/README.md`, `docs/specs/09-access.md`,
   `docs/specs/08-ssh-management.md`, and `docs/DESIGN.md`.
2. Direct source inspection of `src/access.zig`, the access and SSH-key
   handlers in `src/bridge.zig`, `src/sshkeys.zig`,
   `frontend/src/AccessTab.tsx`, `frontend/src/bridge.ts`, and the shell
   integration in `frontend/src/App.tsx`.
3. The focused Zig and frontend test suites plus the existing disposable
   Alpine SSH integration suite.
4. First-party OpenSSH, sudo, systemd, Linux man-pages, and IETF documents.
   The links below are direct primary-source URLs and were checked on
   2026-08-12.

## Verdict

Spec 09 is partially implemented. The backend has useful pure primitives: an
explicit identity registry, fingerprint-based joins, line-hash conflict
guards, scan and job registries, RFC 4180 formatting, and reuse of the
line-preserving SSH-key parser and atomic remote writer. The backend integration
fixture exercises a useful happy path and several conflicts.

The feature is not ready as a product. Remote scan and mutation work blocks the
bridge main thread. Read failures are treated as missing files and can produce
false `complete` coverage. The scan reads only the conventional
`~/.ssh/authorized_keys` path while OpenSSH can use multiple, conditional, or
dynamic sources. Key options and certificate-authority entries are discarded,
so the map overstates who can log in. Rotation does not update the identity
registry. The current frontend is an untyped prototype whose save-person call
does not match the backend payload and whose offboard action never polls the job,
so it never performs the mutation.

## Verified Planned Product Contract

Spec 09 is an app-level fleet view. It must:

- join user-confirmed identities to exact decoded-key fingerprints;
- show observed grants by server and login account, with explicit coverage and
  sync errors;
- keep comments as labels only;
- support selected-grant offboarding, onboarding with a per-server target role,
  and safe fleet rotation;
- preserve every unreadable or unreachable target as an error instead of
  treating it as clean;
- export the last reviewed snapshot as CSV or JSON; and
- require approval for every mutation and type-to-confirm for offboarding.

The product language needs one precision correction. A static key line is an
**observed key grant**, not proof that a person can currently log in. OpenSSH can
disable public-key authentication, deny the account, require another
authentication method, revoke the key, restrict it by source address or expiry,
or trust certificates from other sources. The UI can say “observed access” or
“potential login grant” and can say “login allowed” only when the effective
policy was evaluated for that account and connection context.

## What Exists in the Current Checkout

### Identity registry and people-map logic

`src/access.zig` implements `IdentityStore`, canonical SHA-256 fingerprint
validation, explicit shared-key handling, a pure fingerprint-to-grant join,
unassigned-key grouping, sync-error collection, and CSV/JSON formatting
(`src/access.zig:16-326`, `src/access.zig:754-1077`). This is the correct
identity boundary: `src/sshkeys.zig` computes the fingerprint from the decoded
SSH wire blob, and the access join never uses the comment as authority.

The persisted registry is not crash-safe. `saveLocked` creates and truncates
the final file before it writes and syncs it (`src/access.zig:108-125`). It does
not use a temporary file and atomic rename. It also treats every read error as
an empty registry (`src/access.zig:87-97`), so a permission or I/O failure is
indistinguishable from a file that does not exist.

Identity IDs are not durable. `next_id` starts at 1 on each app start and is not
reconstructed from stored identities (`src/access.zig:76-79`,
`src/access.zig:158-173`). A new identity after restart can reuse an existing
`id-1`. The save path then appends two records with the same ID.

The registry accepts `shared: true`, but the bridge and frontend product flows
do not explain or confirm shared ownership. The frontend wrapper also omits the
`shared` field (`frontend/src/bridge.ts:285-287`).

### Scan coordinator

The scan state model records per-server phases, accounts, grants, coverage,
reasons, and sync errors (`src/access.zig:328-457`). `oars.access.scan` resolves
saved servers, stores a bounded in-memory scan, and `oars.access.poll` advances
each unfinished server before it returns a snapshot (`src/bridge.zig:5850-6140`).
Polls are non-destructive, so two views do not drain each other’s scan results.

The execution model violates the shared threading rule. `accessExec` calls
`Manager.execWait` with a ten-second timeout, and scan polling calls it for
identity, sudo, account enumeration, and sshd configuration work
(`src/bridge.zig:5602-5604`, `src/bridge.zig:5626-5838`). The same poll can wait
on each server sequentially. `sshkeysRead` then waits synchronously for SFTP
stat and read outcomes, with a twenty-second deadline
(`src/bridge.zig:4640-4696`). The shared contract says that the runtime main
thread must never block on network work (`docs/specs/README.md:90-91`). The
current code is not a parallel per-server worker scan, and the claimed typical
two-second per-server target has no benchmark evidence.

The read result is unsafe for coverage. `sshkeysRead` returns `null` for a
missing file, permission failure, timeout, oversized file, malformed response,
or transport failure (`src/bridge.zig:4640-4696`). The access scan treats every
`null` as an inspected empty file and sets `acc.read = true`
(`src/bridge.zig:5747-5780`). An unreadable account can therefore be reported as
clean and can contribute to `coverage: complete`.

A default scan can also return `coverage: complete` after reading only the
connected account (`src/bridge.zig:5651-5671`, `src/bridge.zig:5724-5835`). The
payload has no `scope: connected_account|all_accounts` field, so a consumer can
mistake complete coverage of one account for complete coverage of the server.
Coverage must always state both the requested scope and the achieved scope.

Full-account enumeration is narrower than the contract. It runs only when the
connected session is root; a non-root account with approved non-interactive
sudo is still limited to the connected account (`src/bridge.zig:5651-5678`).
It also drops every account with UID below 1000 except the connected account
(`src/access.zig:642-723`). UID 1000 is a common policy boundary, not an
OpenSSH login rule. `getent` can also report that an NSS database does not
support enumeration, which must produce partial coverage instead of a clean
inventory.

The configuration probe is a raw, case-sensitive `grep` over two paths
(`src/bridge.zig:5808-5833`). It does not evaluate `Include` or `Match`, does
not expand per-account tokens, and does not use `sshd -T -C`. It scans only
`<home>/.ssh/authorized_keys`, although OpenSSH permits multiple
`AuthorizedKeysFile` values and its current default includes both
`.ssh/authorized_keys` and `.ssh/authorized_keys2`. It also does not inspect
`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, or their command forms.

The parser retains every key option (`src/sshkeys.zig:47-67`), but the scan
drops the options when it creates a grant (`src/bridge.zig:5756-5774`). This
loses `from=`, `expiry-time=`, `command=`, `restrict`, and `cert-authority`.
A CA line is consequently presented as if its fingerprint were one person’s
direct login key, even though it can authorize certificates for multiple
principals.

The sudo result is also too coarse. The source model uses `yes|no|unknown`, the
spec example uses a JSON boolean, and the frontend treats every non-empty string
as truthy, so both `no` and `unknown` render as “sudo”
(`src/access.zig:328-335`, `docs/specs/09-access.md:57-59`,
`frontend/src/AccessTab.tsx:64-67`). `parseSudoList` maps any exit-zero listing
to `yes` after two English-message checks (`src/access.zig:628-639`). Sudo rules
can be limited to selected commands or contain negation. The audit model needs
a single explicit vocabulary such as `none|limited|full|unknown`; it must not
turn every successful list operation into full administrative access.

An errored server correctly makes `oars.access.poll` return `state: done` and a
sync error (`src/bridge.zig:6048-6138`). Export uses a different completion
test: `lastFinishedScan` requires every server’s `done` flag, while
`accessFail` leaves that flag false (`src/access.zig:591-603`,
`src/bridge.zig:5596-5599`). A reviewed scan with one sync error can therefore
be shown in the UI but cannot be exported.

The 512 KiB response “row budget” silently stops serializing rows while keeping
the aggregate counts (`src/bridge.zig:5544-5549`, `src/bridge.zig:6064-6115`).
It has no truncation flag, page token, or window request. A large result can
look complete while rows are absent, which is not acceptable for an audit
export or offboard preview.

### Mutation jobs

Offboard and rotate require the identity to own the old fingerprint and require
an expected line hash for each selected grant (`src/bridge.zig:6265-6305`,
`src/bridge.zig:6362-6415`). They reuse the SSH-key rewrite core, which matches
the exact fingerprint and line hash and uses the atomic SFTP save path. This is
the correct concurrent-change guard for one file.

The jobs still run remote SFTP and exec waits inside `oars.access.jobPoll`
(`src/bridge.zig:6432-6504`). A UI poll causes the mutation and can block the
main thread. A job also stops making progress when no view polls it; closing the
view leaves queued items untouched. Registry eviction can destroy the oldest
active scan after 8 scans or the oldest active job after 32 jobs
(`src/access.zig:541-615`).

The approval boundary exists only as intended UI behavior. The backend accepts
offboard, onboard, and rotate requests directly and does not require a prepared,
expiring confirmation token. It records an audit event when the job is queued
and another after a successful item, but it does not store a frozen preview or
the user’s typed confirmation.

Onboarding normalizes the supplied key, but it does not verify that the new
fingerprint belongs to the selected identity (`src/bridge.zig:6315-6350`). A
caller can map person A to fingerprint A and install fingerprint B under person
A’s job. The product contract requires the identity mapping to exist before
the grant job starts.

Rotation directly replaces each old line with the new line. It never changes
the identity registry from the old fingerprint to the new fingerprint
(`src/bridge.zig:6362-6443`). The next scan therefore shows the new key as
unassigned. Direct replacement also cannot satisfy the “nobody loses access”
story across partial fleet failure. A safe fleet rotation needs two stages:
install and verify the new fingerprint on every selected grant, then remove the
old fingerprint only from targets where the first stage succeeded. The identity
change must be committed with a recoverable partial-state record.

Read-only onboarding uses `restrict,command="internal-sftp -R"`, which has a
valid OpenSSH basis: `restrict` disables forwarding, PTY allocation, and
`~/.ssh/rc`, while `sftp-server -R` denies filesystem-changing SFTP requests.
The code must still capability-check the effective server behavior and show
that this is read-only **SFTP**, not a general read-only shell.

### Frontend and bridge contract

`AccessTab` is a 97-line prototype with inline styles, browser prompts, browser
confirm dialogs, and pervasive `any` (`frontend/src/AccessTab.tsx:1-97`). It
does not implement the specified summary counts, last-scanned time, server and
group selection, full-scan approval, person drill-down, attach-unassigned flow,
onboarding, rotation, selected-grant revoke, job progress, or accessible modal
workflows. It is mounted both in the app-level Security section and as a
per-server tab, although Spec 09 defines an app-level fleet view
(`frontend/src/App.tsx:74-80`, `frontend/src/App.tsx:1031-1035`,
`frontend/src/App.tsx:1067-1075`).

The identity save call is currently broken. The backend requires
`{"identity": {...}}` (`src/bridge.zig:5556`,
`src/bridge.zig:6194-6200`), but `api.access.identitiesSave` sends the identity
fields at the payload root (`frontend/src/bridge.ts:285-287`). This also differs
from the flat payload documented in Spec 09. The frontend ignores the failure
inside `loadIdentities`, which hides the cause.

The frontend models scan and job IDs as numbers, but the backend returns strings
such as `scan-1` and `job-1` (`frontend/src/bridge.ts:283-292`,
`src/bridge.zig:5886-5897`, `src/bridge.zig:6245-6255`). No access types exist
in `frontend/src/types.ts`. The scan wrapper does not expose the backend `full`
flag.

The offboard button calls `oars.access.offboard` and displays the returned job
ID, but it never calls `oars.access.jobPoll` (`frontend/src/AccessTab.tsx:69-71`).
Because backend work advances only in `jobPoll`, the button does not revoke a
key. The scan loop stops after 30 attempts even if the backend is still scanning
and does not clear timeouts on unmount (`frontend/src/AccessTab.tsx:19-40`).

Export is not implemented end to end. The backend returns `{format, content}`
(`src/bridge.zig:6530-6565`), while the frontend looks for `path` and reports a
made-up `export.csv` string (`frontend/src/AccessTab.tsx:52`). It does not open a
save dialog or write a file. The product contract should choose one coherent
flow: format from the exact cached scan snapshot, ask for a local destination,
then write locally and report the real path.

The UI also violates the local design contract: it uses nested raw boxes,
untyped status text, color-led error treatment, browser-native blocking dialogs,
and no modal focus management. The finished view needs the same rounded,
bordered, guttered workspace surfaces as the rest of Oars, with one clear
primary action and text labels for every status (`docs/DESIGN.md:130-203`).

## Primary-Source Findings

### Installed key lines are not proof of login reachability

OpenSSH defines an authorized-key line as optional options, key type, encoded
key, and comment, and says the comment is not used for authentication. It also
defines `from=`, `expiry-time=`, forced commands, `restrict`, and
`cert-authority`. These fields change what the key can do or whether it is
accepted. Source:
[OpenBSD sshd(8), AUTHORIZED_KEYS FILE FORMAT](https://man.openbsd.org/sshd.8).

The effective daemon configuration can disable public-key authentication,
require multiple authentication methods, deny users or groups, reject root
login, revoke keys, or trust certificate authorities. Source:
[OpenBSD sshd_config(5)](https://man.openbsd.org/sshd_config).

Consequence: Oars must preserve and classify key options, certificate-authority
entries, account-policy results, and unknowns. The primary table can show
observed grants. It must not state that every listed key can currently log in.

### Effective key sources are account- and connection-dependent

`AuthorizedKeysFile` supports multiple paths, absolute or home-relative paths,
wildcards, and `%h`, `%U`, and `%u` expansion. `AuthorizedKeysCommand` can add a
dynamic source. `Include` and `Match` can change settings for a user, group,
address, host, or port. OpenSSH provides `sshd -T -C ...` to output the effective
configuration with applicable `Match` rules. Sources:
[OpenBSD sshd_config(5)](https://man.openbsd.org/sshd_config) and
[OpenBSD sshd(8), `-T` and `-C`](https://man.openbsd.org/sshd.8).

Consequence: a complete scan must evaluate effective settings per account and
the relevant connection context, then inspect every expanded static source. It
must remain partial when a command, certificate source, unsupported token,
source-address condition, or unreadable path prevents a full evaluation.

### File state and permissions affect authentication

OpenSSH says `~/.ssh/authorized_keys` lists login keys, recommends user-only
write access, and refuses to use it under normal `StrictModes` when the file,
`.ssh` directory, or home directory is writable by other users. Source:
[OpenBSD sshd(8), FILES](https://man.openbsd.org/sshd.8).

Consequence: “file missing”, “file empty”, “file unreadable”, “unsafe
permissions”, and “transport failed” are different scan outcomes. Only the first
two can be clean observations, and unsafe permissions can mean the installed key
is not currently usable.

### Sudo is a policy, not a reliable boolean

The sudoers policy supports command-specific allow and deny rules. The `list`
built-in controls who may use `sudo -l -U otheruser`; by default that authority
is limited to root or a user with broad matching privileges. Non-interactive
authentication can also fail when an authentication method needs terminal
input. Sources:
[sudoers(5), official sudo 1.9.14 manual](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)
and the official sudo project’s
[`-ll` policy-listing example](https://www.sudo.ws/posts/2023/11/more-info-with-ll-in-sudo-1.9.15/).

Consequence: Oars must distinguish no sudo rules, limited rules, full
administrative rules, and unknown policy. A localized output string plus exit
zero is not enough to claim full sudo access.

### Account enumeration must use the platform account database honestly

`getent passwd` queries the Name Service Switch database, not only
`/etc/passwd`, and can return exit 3 when a database does not support
enumeration. Source:
[Linux man-pages getent(1)](https://man7.org/linux/man-pages/man1/getent.1.html).
Systemd’s account tools also expose users from NSS and user-record services and
do not apply a UID filter unless asked. Source:
[systemd userdbctl(1)](https://www.freedesktop.org/software/systemd/man/latest/userdbctl.html).

Consequence: Oars can use `getent` as one adapter, but it must inspect all
returned accounts that can be SSH targets, report enumeration-not-supported as
partial, and avoid a hard-coded UID 1000 completeness rule.

### The read-only role is a read-only SFTP capability

OpenSSH says `restrict` disables port, agent, and X11 forwarding, PTY
allocation, and `~/.ssh/rc`. It says `sftp-server -R` rejects write opens and
other filesystem-changing requests. Sources:
[OpenBSD sshd(8)](https://man.openbsd.org/sshd.8) and
[OpenBSD sftp-server(8)](https://man.openbsd.org/sftp-server.8).

Consequence: the product can offer a read-only SFTP role when the server
supports these features. It must not label it as a read-only shell.

### CSV formatting

RFC 4180 defines comma-separated records, CRLF row endings, quoted fields for
commas, quotes, and line breaks, and doubled embedded quotes. Source:
[IETF RFC 4180](https://www.rfc-editor.org/rfc/rfc4180).
The pure formatter follows these rules, but the UI still needs a real local save
flow and the export must carry an explicit partial/truncated state.

## Required Implementation Work

1. **Move remote work off the bridge thread.** Add a bounded access coordinator
   that queues per-server scan and mutation operations on session workers.
   `scan`, `poll`, and `jobPoll` must only create jobs or read snapshots. Jobs
   must continue when the view closes.
2. **Make scan outcomes lossless.** Give SFTP and exec probes typed outcomes for
   missing, denied, timeout, transport failure, too large, and parse failure.
   Only a confirmed missing file is an empty inventory. Preserve all errors in
   account coverage.
3. **Evaluate effective OpenSSH policy.** Use a capability-detected
   `sshd -T -C` adapter when authority permits it. Parse all effective static
   key files, options, certificate sources, account eligibility controls, and
   dynamic-source reasons. Keep coverage partial when the effective policy
   cannot be proven.
4. **Fix account and sudo semantics.** Enumerate the platform account database
   without a hard-coded UID cutoff, classify non-enumerable sources, and use one
   typed sudo vocabulary: `none|limited|full|unknown` with evidence per account.
5. **Harden identity persistence.** Recover the next ID from stored records or
   use random IDs, reject duplicate IDs, distinguish not-found from read errors,
   and save through a mode-0600 temporary file plus atomic rename.
6. **Bind every mutation to a reviewed snapshot.** Prepare an expiring token
   containing identity revision, selected fingerprint grants, line hashes,
   target accounts, and role policy. Commit must require that token plus the
   required confirmation. Keep per-item success and failure evidence.
7. **Repair onboarding and rotation.** Onboarding must verify or atomically add
   the supplied fingerprint to the identity before it queues grants. Rotation
   must add and verify the new key first, remove the old key second, update the
   identity registry, and preserve a recoverable partial state.
8. **Make large scans explicit.** Add page/window parameters or a local snapshot
   query. Never silently omit rows. Export must use the exact reviewed snapshot,
   include coverage and sync-error metadata, and remain possible when some
   servers have sync errors.
9. **Replace the Access prototype.** Build the app-level people table,
   unassigned review, person detail, add/offboard/rotate dialogs, per-server
   progress, export dialog, and responsive states from the design contract.
   Remove the duplicate per-server Access tab unless it becomes a scoped link
   into the app-level view.
10. **Add shared TypeScript contracts and UI tests.** Use string scan/job IDs,
    type all payloads and responses, fix the identity-save shape, expose full
    scan, clean up polling timers, and test every dialog and job lifecycle.

## Verification Performed

- `ZIG_GLOBAL_CACHE_DIR=/private/tmp/oars-spec09-zig-cache zig test src/access.zig`
  passed: 9/9 focused access tests.
- `npm test -- --run` passed: 10 files and 93 tests. No test imports or renders
  `AccessTab`, so this does not verify the access UI.
- `npx tsc --noEmit` passed. The access bridge still compiles because its
  responses and most payload fields use `any`.
- `./scripts/integration-test.sh` uses the existing disposable Alpine SSH and
  MinIO fixtures and runs `zig build -j1 test`. The live run passed 232 of 233
  tests, including the Spec 09 access integration. The only failure was the
  unrelated VNC integration at `src/integration_vnc.zig:472`, where its remote
  setup command returned 1 instead of 0. The script shut the fixtures down.

## Source Index

- OpenSSH daemon and authorized-key format:
  <https://man.openbsd.org/sshd.8>
- OpenSSH daemon configuration:
  <https://man.openbsd.org/sshd_config>
- OpenSSH SFTP server read-only mode:
  <https://man.openbsd.org/sftp-server.8>
- Official sudoers manual:
  <https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf>
- Official sudo policy-listing example:
  <https://www.sudo.ws/posts/2023/11/more-info-with-ll-in-sudo-1.9.15/>
- Linux `getent` manual from the upstream Linux man-pages project:
  <https://man7.org/linux/man-pages/man1/getent.1.html>
- systemd account database tool:
  <https://www.freedesktop.org/software/systemd/man/latest/userdbctl.html>
- RFC 4180:
  <https://www.rfc-editor.org/rfc/rfc4180>
