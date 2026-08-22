# Next Spec Implementation Guide

> Source audit and external research observed **2026-08-21** at commit
> `bc2aa83`. This guide separates code that exists in this checkout from work
> still required for release.

## Target

Implement and finish **Spec 10 — Backups**. Treat
`docs/specs/10-backups.md` as the product contract, but use the corrected
contracts and architecture below where the current source audit or primary
rclone/Cronie documentation disproves an existing assumption.

Spec 10 is still listed as Planned in the feature index
(`docs/specs/README.md:12-24`), although a substantial backend slice and a
placeholder frontend already exist. Do not mark it complete merely because
most acceptance boxes in the spec are checked. Completion requires the
release gates in this guide, especially nonblocking handlers, truthful
scheduled-run import, cancellation and cleanup, working Keychain flows, typed
frontend state, deterministic previews, and a real cron integration leg.

After Spec 10 is complete, the next implementation guide is **Spec 11 — AI
Terminal**.

## Files to read before editing

Read these together; no one file describes the current truth:

- `docs/specs/README.md:1-100` — implementation truth, stream cursors, secrets,
  approvals, errors, shell quoting, cancellation, research, and session-worker
  rules
- `docs/DESIGN.md:1-25`, `docs/DESIGN.md:41-65`,
  `docs/DESIGN.md:130-203`, and `docs/DESIGN.md:213-217` — calm operational
  language, responsive layout, status semantics, modal requirements, and theme
  constraints
- `docs/specs/10-backups.md:1-250` — product scope, current bridge draft,
  security model, tests, acceptance claims, and existing references
- `src/backup.zig:1-276` — bounds, provider/job model, validation, and schedule
  model
- `src/backup.zig:278-550` — cron parsing/editing, rclone config generation,
  destination construction, and scheduled wrapper generation
- `src/backup.zig:552-850` — JSON-log parsing and history persistence
- `src/backup.zig:856-1211` — job persistence, live-run registry, and registry
  ownership
- `src/backup.zig:1213-1624` — current unit coverage
- backup payloads and handlers in `src/bridge.zig:11288-12124`
- synchronous SFTP helpers currently reused by backups in
  `src/bridge.zig:4618-4727`
- `src/sessions.zig:1-8`, `src/sessions.zig:76-178`,
  `src/sessions.zig:1281-1365`, `src/sessions.zig:1710-1799`, and
  `src/sessions.zig:2016-2027` — worker ownership, non-destructive streams,
  secret stdin, coordinator-safe waits, channel-close limitations, and the
  asynchronous outcome pattern
- `src/keyjobs.zig:1-30`, `src/keyjobs.zig:643-720`, and
  `src/keyjobs.zig:800-857` — the closest existing bounded coordinator,
  idempotency, plan, cancellation, and poll-observer design
- `src/integration_backup.zig:1-240` and backup setup in
  `src/integration.zig:24-45`, `src/integration.zig:67-169`
- `scripts/dev-sshd/Dockerfile:14-35`, `scripts/dev-sshd.sh`, and
  `scripts/integration-test.sh:1-23` — the real Alpine/MinIO harness
- `frontend/src/BackupsTab.tsx:1-277`
- `frontend/src/bridge.ts:90-176` and `frontend/src/bridge.ts:441-488`
- `frontend/src/types.ts:575-708`
- `frontend/src/App.tsx:71-104`, `frontend/src/App.tsx:1015-1025`, and
  `frontend/src/App.tsx:1271-1293`
- the only current focused backup-adjacent frontend assertion in
  `frontend/src/modal-a11y-challenge.test.tsx:899-924`
- `frontend/preview.html:13-30`, `frontend/preview.html:205-260`, and the bridge
  fixture dispatcher beginning at `frontend/preview.html:419`; every state in
  this guide needs a deterministic backup fixture

## Verified implemented baseline

This section records only code present in commit `bc2aa83`. It is not the
remaining implementation plan.

### Backend model and persistence already exist

`src/backup.zig` already provides:

- bounded name/source/bucket/endpoint/prefix/cron constants, 90-day history,
  a 200 KiB stored-log cap, and a one-manual-run-per-server policy
  (`src/backup.zig:14-29`)
- provider, destination, transfer, schedule, job, and validation types
  (`src/backup.zig:30-276`)
- a five-field numeric cron parser, interval-to-cron conversion, percent
  escaping, and marker-based crontab add/remove helpers
  (`src/backup.zig:278-414`)
- rclone INI section generation and section-preserving merge logic
  (`src/backup.zig:416-505`)
- a generated scheduled wrapper and staged status/log paths
  (`src/backup.zig:516-550`)
- JSON-line stats/error parsing (`src/backup.zig:552-648`)
- local run-history persistence with quarantine, retention, idempotent run IDs,
  and newest-first reads (`src/backup.zig:650-850`)
- local job persistence with quarantine and CRUD (`src/backup.zig:856-1088`)
- an in-memory live-run registry retaining 16 completed runs
  (`src/backup.zig:1090-1211`)

The unit tests cover the current validation matrix, cron syntax, marker
round-trips, percent escaping, rclone config/merge output, log parsing, history
retention/log trimming, job CRUD, and live-run limits
(`src/backup.zig:1213-1624`).

### Bridge and MinIO pipeline already exist

The dispatcher registers nine `oars.backup.*` commands
(`src/bridge.zig:147-157`, `src/bridge.zig:269-277`). Current handlers can:

- list and persist local jobs
- write/remove schedule artifacts and crontab blocks
- run a real sentinel capability sequence
- start a manual tracked rclone channel
- expose caller-owned log cursors and progress snapshots
- persist history
- generate limited Alpine/Debian install commands
- probe rclone/cron presence

The current MinIO integration test creates a real job, performs the sentinel
sequence, runs a two-file sync, verifies an unchanged run as `no_changes`,
performs an incremental run, checks history, and verifies landed objects
(`src/integration_backup.zig:110-240`). The harness installs rclone in the
Alpine SSH image and supplies a separate MinIO container
(`scripts/dev-sshd/Dockerfile:14-35`; `src/integration_backup.zig:1-19`).

### Typed bridge declarations exist, but the screen does not use them

`frontend/src/types.ts:575-708` defines jobs, credentials, runs, polls,
install results, and cron status. `frontend/src/bridge.ts:441-488` wraps the
current backend commands.

`BackupsTab` is only a placeholder. It stores jobs and editor state as `any`,
uses legacy `paths`, `retention_days`, and string `schedule` fields that do not
exist in the backend model, sends no Keychain credentials, and turns status or
history into transient text (`frontend/src/BackupsTab.tsx:10-59`,
`frontend/src/BackupsTab.tsx:65-196`). Its modal exposes only name, comma-
separated paths, hourly/daily/weekly, and retention days
(`frontend/src/BackupsTab.tsx:210-277`). The only focused test checks modal
focus and Escape dismissal (`frontend/src/modal-a11y-challenge.test.tsx:899-924`).
There is no backup state module or focused backup integration test.

The deterministic preview has modes for logs, VNC, files, scripts, deployment,
access, and keys, but no `backups` mode or `oars.backup.*` fixture
(`frontend/preview.html:13-30`, dispatcher at `frontend/preview.html:419`).

### Verification status for this research pass

No build or test suite was run during this documentation-only audit. The
baseline above comes from source inspection and the checked-in test code; it is
not a claim that those tests pass in this checkout on 2026-08-21.

## Prioritized release blockers

### P0 — bridge handlers block the runtime main thread

Every backup probe calls `backupExec`, which calls `Manager.execWait`
(`src/bridge.zig:11347-11360`). Schedule save/remove, staged import, connection
test, source validation, installation, and cron status therefore wait on SSH
from bridge handlers (`src/bridge.zig:11402-11500`,
`src/bridge.zig:11514-11579`, `src/bridge.zig:11614-11853`,
`src/bridge.zig:12046-12123`). Config reads/writes also reuse synchronous SFTP
wait loops (`src/bridge.zig:4618-4727`).

This violates the explicit main-thread rule in `src/bridge.zig:1-6` and
`src/sessions.zig:1-8`. A timeout bounds the freeze; it does not make the call
nonblocking.

Move all remote backup work into a bounded backup coordinator that communicates
with the owning session worker through queued outcomes. Bridge handlers may
validate/copy bounded input, register plans/operations/runs, and serialize
locked local snapshots. They must not call `execWait`, `SftpOutcome.wait`,
`sleep`, or any network API. Poll handlers only observe copied state and never
start, advance, finalize, import, or clean an operation.

### P0 — scheduled runs cannot be imported truthfully

The staged-import path is not release-ready:

- the wrapper writes numeric JSON values, while `BackupStatusFile` declares all
  fields as strings (`src/backup.zig:528-547`; `src/bridge.zig:11502-11508`)
- import attempts to execute `<timestamp>.status` and `<timestamp>.log` as shell
  commands instead of reading them (`src/bridge.zig:11526-11545`)
- the scheduled invocation omits `--use-json-log`, `--stats`, and
  `--stats-log-level`, although import parses JSON stats
  (`src/bridge.zig:11423-11435`, `src/bridge.zig:11470-11476`)
- the wrapper does not perform the manual path’s source-existence check
- a failed lock exits without a status record, so overlap is invisible
- status/log publication is not atomic, staged files are not bounded while
  retained, and remote retention is absent
- import and deletion use unquoted shell paths (`src/bridge.zig:11517-11578`)
- importing is triggered synchronously by list/history calls
  (`src/bridge.zig:11582-11611`, `src/bridge.zig:12017-12043`)

Replace this with a versioned, bounded staging protocol described below and add
a real cron-daemon integration leg in which Oars is disconnected while the job
runs.

### P0 — local and remote mutations are not transactional

`jobs.save` writes `backups.json` before schedule installation; a later remote
failure returns an error while leaving the local job committed
(`src/bridge.zig:11614-11658`). The generated ID counter restarts at `1` and
does not check generated IDs against persisted jobs, so a process restart can
create duplicate `bk-1` IDs (`src/backup.zig:858-864`,
`src/backup.zig:936-995`).

`jobs.delete` deletes locally before checking the job’s server ownership or
removing its schedule. A caller-supplied `server_id` can name a different
server, and a disconnected scheduled job can be deleted locally while its
cron/config/wrapper remain active remotely (`src/bridge.zig:11661-11677`). An
edit can also change `server_id` without cleaning the former server.

Use cryptographically random stable string IDs, immutable `server_id`, a
monotonic `revision`, frozen mutation plans, whole-plan hashes, and
frontend-generated `operation_id` idempotency. For schedule-enabled jobs,
remote prepare/verify must succeed before the local atomic commit. Delete must
verify job ownership, remove and read back the exact remote artifacts, then
commit the local deletion. Partial cleanup is retained as an actionable
operation; it is never reported as success.

### P0 — cancellation and cleanup are missing or poll-driven

There is no backup cancel command. Closing an SSH channel is not proof that the
remote rclone process stopped; the repository explicitly says so
(`docs/specs/README.md:78-81`). Manual config removal, history append, run
finalization, and completed-run eviction happen only inside
`handleBackupPoll` (`src/bridge.zig:11895-12003`). If the UI stops polling,
cleanup and durable completion do not happen.

The backup coordinator must own completion independently of the UI. Manual
runs start in a tracked remote process group, record the group identity, and on
cancel send `TERM`, wait to a bounded deadline, then send `KILL` if necessary
and verify the process group is gone. Only then may the run become `canceled`.
A channel close is transport cleanup after process termination, not the cancel
mechanism. Every terminal path removes the unique temporary config; a failed
removal produces `partial`/`cleanup_failed` with the exact leftover path.
Disconnect without verified termination is `interrupted`, not `canceled`.

### P0 — the secret flow is not wired end to end

The backend comments promise `backup:<job_id>` Keychain storage, but the bridge
cannot access Keychain and `BackupsTab` never calls it. Default form save enables
a schedule without credentials (`frontend/src/BackupsTab.tsx:35-53`), and Run
now also sends none (`frontend/src/BackupsTab.tsx:121-143`). Both paths fail for
non-IAM jobs.

Credential strings are not bounded or validated against INI line injection,
backend-owned copies are not explicitly zeroed, and there is no backup-specific
transient Keychain path. `vault.get`/`set` currently populate a process-lifetime
cache (`frontend/src/bridge.ts:119-176`), which must not retain bucket secrets.

Implement the Keychain, memory, disclosure, and cleanup rules in this guide
before considering schedules complete.

### P1 — current backend/frontend contracts disagree

The frontend overload allows `api.backup.test(serverId, jobId)` and sends
`{server_id, job_id}` (`frontend/src/bridge.ts:451-461`), but the backend accepts
only `{job, credentials?}` (`src/bridge.zig:11309-11312`). The Test button uses
the incompatible overload (`frontend/src/BackupsTab.tsx:147-160`).

The screen reads nonexistent `j.schedule`, `j.retention_days`, `j.paths` shapes
instead of `schedule`, `source_path`, and `destination`
(`frontend/src/BackupsTab.tsx:111-176`). Backend timestamps are nanoseconds,
which exceed JavaScript’s exact integer range, while frontend types use
`number` (`src/bridge.zig:11399`; `frontend/src/types.ts:605-615`). Backend
status includes `interrupted`; frontend includes `queued` and `canceled` but
not `interrupted` (`src/backup.zig:652-667`; `frontend/src/types.ts:579-584`).

Replace the contract on both sides at once. Send timestamps as integer
milliseconds and remove all backup `any`/legacy fallback fields.

### P1 — provider adapters and generated rclone config are inaccurate

Primary rclone S3 documentation (<https://rclone.org/s3/>) requires these corrections:

- AWS runtime/IAM credentials require blank key fields **and**
  `env_auth = true`; current IAM generation merely omits keys
  (`src/backup.zig:423-465`).
- rclone’s S3 provider list has no `B2` provider value. Backblaze’s
  S3-compatible endpoint must use the tested `Other` S3 adapter (or a separate
  native B2 product, which is out of scope); current code emits `provider = B2`
  (`src/backup.zig:54-63`).
- R2’s documented S3 adapter is `Cloudflare`, with region `auto` and a required
  endpoint.
- storage classes are provider-specific. Current non-AWS adapters all expose
  `standard`, `standard_ia`, and `onezone_ia`, although rclone documents those
  options only for named providers and classes (`src/backup.zig:80-101`).
- default/unsupported storage class must be omitted, not emitted universally.
- rclone JSON logging places transfer statistics in structured records
  (<https://rclone.org/docs/#logging>). Current parsing never reads total
  transfer count, so `files_total` is always zero (`src/backup.zig:569-623`).

Create immutable provider-adapter tables that own rclone provider value,
required fields, fixed/default region, endpoint policy, IAM support, and exact
storage-class options. Generate golden configs for every adapter.

### P1 — Test Connection does not prove a read

The current “read” step calls `rclone lsf` again, which proves listing but not
object content read (`src/bridge.zig:11765-11780`). The cleanup verification
also executes the same list twice (`src/bridge.zig:11784-11793`).

The capability operation must list the exact prefix, write a nonce-bound
sentinel, read its bytes back with `rclone cat` and compare the complete known
content, delete that exact object, then prove it is absent. A sync job uses the
same exact-object delete proof; do not use a broad delete pattern. Cleanup runs
in a `defer`-equivalent terminal path after every post-write error. A leftover
sentinel makes the operation `partial`, returns its exact remote object path,
and blocks save.

### P1 — interval schedules and cron management are not truthful

`intervalToCronExpr` silently caps hours at 23 and days at 31 and uses field
steps (`src/backup.zig:343-349`). Cronie's `crontab(5)` documentation
(<https://github.com/cronie-crond/cronie/blob/master/man/crontab.5>) states that
steps operate within
the selected calendar field: `*/23` in hours runs at hours 0 and 23, not every
23 elapsed hours. `0 0 */N * *` also resets within each month and is not a
continuous N-day interval. The parser claims range-step support but checks the
hyphen branch before the slash branch, so `1-5/2` is rejected
(`src/backup.zig:302-340`).

For interval mode, install a once-per-minute marker entry and let the generated
wrapper compare a persisted UTC `next_due_epoch` against `date +%s`. Advance
from the previous due time until it is in the future so delayed cron ticks do
not drift the anchor. Define one day as 24 elapsed hours. Custom mode remains a
validated five-field expression interpreted in the server cron daemon’s local
timezone. The UI must state this difference and warn that local custom times
can be skipped or repeated at daylight-saving transitions.

Never interpolate a crontab into `printf`. Read the current table, retain its
exact bytes, freeze its SHA-256 in the plan, re-read before commit, edit only the
exact `# oars:job:<id>` two-line block, validate, install through bounded stdin,
and read back. A duplicate/malformed marker is a conflict. Detect and use
Cronie `crontab -T`; otherwise apply the exact internal subset and rely on
install/readback. Every table ends with a newline.

### P1 — install/status probing is guessed and not approval-safe

The current code recognizes Alpine/Debian text only, assumes root, emits package
commands immediately, checks for `crond` even on Debian, and uses `pgrep` for
service truth (`src/bridge.zig:12046-12123`). It does not return architecture,
package source, service manager, privilege, or a verified plan as required by
the spec.

Probe OS ID/version, architecture, package manager, service manager, privilege,
rclone path/version, crontab implementation, daemon/service state, server
home, timezone, `date +%s`, and process-group capability. Return a frozen plan
with exact packages, repositories/download source, privilege, commands,
service actions, and rollback/partial effects. Commit only a non-expired plan
with an `operation_id`. Unknown targets return manual instructions and never
execute a guessed command.

### P1 — bounds, typed failures, and persistence need hardening

Current job/history files are rewritten in place rather than sibling-temp +
sync + rename (`src/backup.zig:760-778`, `src/backup.zig:912-925`). Job count,
history request limit, IDs, credentials, and operation registries are not all
bounded. Several distinct failures collapse to false/null or generic strings.

Adopt the exact bounds and typed errors below. Quarantine corrupt local files,
write local stores atomically, and expose recovery errors. Never turn denied,
timeout, too-large, malformed, or transport failures into “missing” or an empty
successful state.

### P1 — the product screen is not an implementation of Spec 10

Replace the placeholder with the product flow below. It must show runtime
readiness, exact source/destination, transfer semantics, server timezone,
credential mode/presence, schedule state, last run, live progress/log,
import/cleanup warnings, and history. It must make `sync` deletion consequences
unmistakable without turning the whole page into an alarm surface.

## Corrected product flow

Backups remains available both as a per-server tab and in Protection → Backups.
Both surfaces use one controller keyed by `server_id`; they do not create
independent pollers for the same server.

1. **Initial load.** Read local jobs and cached runtime status immediately. A
   background refresh operation probes the connected server and imports staged
   scheduled records. Keep the last completed snapshot visible while refreshing.
2. **Disconnected.** Jobs/history remain visible and are labeled stale. Manual
   local metadata edits may be drafted, but remote tests, runs, schedule changes,
   installs, and scheduled-job deletion are blocked. Never show “no jobs” because
   a remote refresh failed.
3. **Runtime attention.** One restrained status section names missing rclone,
   missing/stopped cron, unsupported scheduler, stale imports, or cleanup tasks.
   Offer one relevant action, not separate raw probe buttons.
4. **Ready list.** Each row shows name, exact source → bucket/prefix, Copy or
   Sync, schedule in human language, credential mode, and last run. Actions are
   Run now, View run, Edit, and Delete. Keep seven or fewer visible columns.
5. **Create/edit.** Use progressive sections: basics; provider/destination;
   credentials; transfer consequence; schedule; Test Connection; review. Save is
   disabled until required fields and a current capability proof exist.
6. **Run.** Show current phase, bytes, files, speed, ETA, elapsed time, bounded
   live log, cancel, and cleanup state. `No changes` is a success state. Keep the
   last snapshot visible if polling or connection fails.
7. **History.** Show the last 20 summaries. Load raw log chunks only when a run
   detail opens; do not embed every log in the history list response.
8. **Partial recovery.** A leftover sentinel/config/wrapper/crontab block is a
   named cleanup task with exact path and Retry cleanup. Never hide it behind a
   generic toast.

### Create/edit sequence

1. Build a typed draft and request `jobs.plan`. The backend normalizes it,
   allocates a random ID for a new job, freezes the expected job revision and
   remote mutation identities, and returns effects/disclosures.
2. For non-IAM S3, collect access/secret keys in secret inputs. Test through
   `test.plan` → explicit approval → `test`. The proof is bound to provider,
   endpoint, region, bucket, prefix, transfer kind, and credential mode.
3. Store non-IAM credentials in Keychain under `backup:<job_id>` through the
   backup-specific no-cache method. A Keychain failure blocks save.
4. Commit `jobs.save`. If an unattended schedule needs credentials, read them
   transiently from Keychain and send them only in this commit after the remote-
   secret disclosure is accepted.
5. Poll the operation. Close/zero secret state immediately after admission.
   Refresh local jobs only after the operation reaches `done`.
6. On a failed new-job commit, delete the just-created Keychain entry. On edit,
   retain the former credential until the new remote/local commit succeeds.

A prior capability proof remains valid only while all bound destination/auth/
transfer fields are unchanged and for at most 10 minutes. Source-only and
schedule-only edits may reuse a still-valid proof.

### Run and delete approvals

- Copy: confirmation states that changed/new files are uploaded and destination
  extras are retained, matching rclone's copy contract
  (<https://rclone.org/commands/rclone_copy/>).
- Sync: require the exact job name for every manual run because rclone sync can
  delete destination extras (<https://rclone.org/commands/rclone_sync/>).
  Enabling a sync schedule requires the same typed
  confirmation and records advance approval for later cron runs.
- Test Connection: show the exact sentinel object path and list/write/read/delete
  operations before approval.
- Delete: require the exact job name and show crontab block, wrapper/state path,
  dedicated config section, staged records, local history policy, and Keychain
  account. Do not delete destination objects.
- Install/start: show exact package/source, privilege, service action, and target
  before commit.

## Exact backend contract

### Common envelopes

All user-facing failures resolve through the bridge as:

```ts
type BackupErrorCode =
  | "invalid_payload" | "invalid_job" | "invalid_credentials"
  | "not_connected" | "session_not_ready" | "unsupported_target"
  | "rclone_missing" | "cron_missing" | "cron_stopped"
  | "source_missing" | "source_unreadable" | "source_too_large"
  | "plan_expired" | "conflict" | "busy" | "not_found"
  | "permission_denied" | "timeout" | "transport_error"
  | "capability_failed" | "cleanup_failed" | "store_corrupt"
  | "canceled" | "interrupted" | "internal";

type BackupFailure = {
  ok: false;
  code: BackupErrorCode;
  error: string;              // human, secret-free
  retryable: boolean;
  detail?: { step?: string; path?: string; remote_object?: string };
};
```

Update `invoke`/`BridgeError` so the backend `code` survives instead of becoming
only `command_failed` (`frontend/src/bridge.ts:90-116`). Transport/framework
rejections remain bridge exceptions.

All IDs are strings. All timestamps on the wire are integer milliseconds. All
operation IDs are frontend-generated random UUIDs and are idempotency keys.

```ts
type BackupOperationState =
  | "queued" | "running" | "done" | "partial" | "failed" | "canceled";

type BackupStepState =
  | "pending" | "running" | "done" | "conflict" | "failed"
  | "cancel_requested" | "canceled" | "skipped";

type BackupOperation = {
  ok: true;
  operation_id: string;
  kind: "refresh" | "test" | "save" | "delete" | "install" | "cleanup";
  state: BackupOperationState;
  steps: Array<{ id: string; state: BackupStepState; error?: BackupFailure }>;
  started_at_ms: number;
  finished_at_ms?: number;
  result?: unknown;
  error?: BackupFailure;
};
```

### Job model

```ts
type BackupProvider = "aws" | "r2" | "b2_s3" | "wasabi" | "minio" | "spaces";
type BackupTransfer = "copy" | "sync";
type BackupCredentialMode = "access_key" | "aws_runtime";

type BackupDestination = {
  type: "s3";
  provider: BackupProvider;
  bucket: string;
  prefix: string;
  endpoint: string;
  region: string;
  credential_mode: BackupCredentialMode;
  storage_class: string; // "" means provider default; adapter allow-list only
};

type BackupSchedule =
  | { mode: "manual"; enabled: false }
  | { mode: "interval"; enabled: boolean; every: number; unit: "hours" | "days";
      anchor_epoch_sec: number }
  | { mode: "custom"; enabled: boolean; expr: string };

type BackupJob = {
  id: string;
  server_id: string;
  revision: number;
  name: string;
  source_path: string;
  destination: BackupDestination;
  transfer: BackupTransfer;
  schedule: BackupSchedule;
  capability_proof?: { id: string; expires_at_ms: number; binding_sha256: string };
  created_at_ms: number;
  updated_at_ms: number;
};
```

Local destination remains modeled only as a disabled Oars+ choice. Do not keep
`"local"` in the shipping v1 union while execution is absent.

### Read, plan, operation, and history commands

```text
oars.backup.jobs.list
  {server_id}
  -> {ok:true, jobs:BackupJob[], recovery_error?:string}

  Local-only. Never probes/imports. Sorted by updated_at_ms then stable id.

oars.backup.status
  {server_id}
  -> {ok:true, status:BackupServerStatus|null, stale:boolean}

  Local cached snapshot only.

oars.backup.refresh
  {operation_id, server_id}
  -> {ok:true, operation_id}

  Coalesces an active refresh for the server. Probes runtime and imports staged
  records on the coordinator.

oars.backup.jobs.plan
  {job:BackupJobDraft, expected_revision?:number}
  -> {ok:true, plan_id, expires_at_ms, job:BackupJob,
      requires_connection_test, requires_remote_secret,
      effects:string[], warnings:string[], schedule_preview?:{timezone, crontab_block}}

oars.backup.jobs.save
  {operation_id, plan_id, capability_proof_id?, schedule_credentials?,
   approved_remote_secret:boolean}
  -> {ok:true, operation_id, job_id}

oars.backup.jobs.deletePlan
  {server_id, job_id, expected_revision}
  -> {ok:true, plan_id, expires_at_ms, job_name, effects:string[], leftovers:string[]}

oars.backup.jobs.delete
  {operation_id, plan_id, confirm_job_name}
  -> {ok:true, operation_id}

oars.backup.operationPoll
  {operation_id}
  -> BackupOperation

oars.backup.operationCancel
  {operation_id}
  -> {ok:true}

oars.backup.history
  {server_id, job_id, limit?:number}
  -> {ok:true, runs:BackupRunSummary[]}

oars.backup.historyLog
  {server_id, run_id, cursor?:number, max?:number}
  -> {ok:true, cursor, delta, eof, dropped}
```

`jobs.list`, `status`, `history`, and `historyLog` verify server/job/run
ownership. `limit` defaults to 20 and clamps to 20. `historyLog.max` defaults to
32 KiB and clamps to 64 KiB.

### Connection test

```text
oars.backup.test.plan
  {job_plan_id}
  -> {ok:true, test_plan_id, expires_at_ms, remote_object,
      checks:["list","write","read","delete","cleanup_verify"],
      mutates:true}

oars.backup.test
  {operation_id, test_plan_id, credentials?}
  -> {ok:true, operation_id}
```

The terminal operation result is:

```ts
{
  checks: {
    list: "passed" | "failed";
    write: "passed" | "failed";
    read: "passed" | "failed";
    delete: "passed" | "failed";
    cleanup_verify: "passed" | "failed";
  };
  capability_proof?: { id: string; expires_at_ms: number; binding_sha256: string };
  leftover_remote_object?: string;
}
```

IAM mode sends no credentials. Access-key mode requires both non-empty fields.
The operation always attempts exact sentinel cleanup after write admission.

### Manual run

```text
oars.backup.run
  {operation_id, server_id, job_id, expected_revision, credentials?,
   confirm_job_name?:string}
  -> {ok:true, run_id}

oars.backup.poll
  {run_id, log_cursor?:number}
  -> {ok:true, run_id,
      status:"queued"|"preparing"|"running"|"cancel_requested"|
             "success"|"no_changes"|"failed"|"canceled"|"interrupted"|"partial",
      phase, bytes_done, bytes_total, files_done, files_total,
      speed_bps, eta_sec, started_at_ms, finished_at_ms?,
      log_cursor, log_delta, dropped, cleanup_state, error?:BackupFailure}

oars.backup.cancel
  {run_id}
  -> {ok:true}
```

A repeated run `operation_id` returns the same run. `log_cursor` is caller-owned
and non-destructive. Polling cannot start/finalize/cancel/clean the run.
`files_total` comes from rclone `stats.totalTransfers`, while `files_done` comes
from `stats.transfers`. Exit 0 plus zero completed transfers is `no_changes`.
Never enable `--error-on-no-transfer`.

### Runtime/install

```text
oars.backup.install.plan
  {server_id, what:"rclone"|"cron"|"start_cron"}
  -> {ok:true, plan_id, expires_at_ms, target, privilege,
      commands:string[], effects:string[], rollback:string[], manual:boolean}

oars.backup.install
  {operation_id, plan_id}
  -> {ok:true, operation_id}
```

`BackupServerStatus` contains observed time, OS/arch, connected user/home,
timezone, rclone path/version, crontab implementation, cron installed/running,
service manager, scheduler support, and import/cleanup warnings. Replace the old
synchronous `cronStatus` endpoint with `status` + `refresh`; do not keep two
probing paths.

## Core architecture and worker rules

### Registry and coordinator

Evolve `backup.Registry` into the single owner of plans, operations, runs,
cached server status, jobs, and history. Follow the bounded pattern in
`src/keyjobs.zig:643-720`:

- one coordinator thread advances short backup state machines
- long rclone transfers remain channels owned/pumped by the per-session worker;
  the coordinator samples their streams and finalizes them
- feature-specific bounded exec/SFTP outcomes are queued through
  `sessions.Manager`; no libssh2 call leaves the owning session worker
- no registry/store lock is held while waiting on an outcome or writing a file
- active records are never evicted
- coordinator shutdown requests cancellation, joins, marks unverified remote
  work `interrupted`, clears secrets, and preserves cleanup records
- operation/run poll serializers copy under a short lock and serialize after
  unlocking

Use `execTrackedWithInput` semantics for generated config/crontab bytes so
secret/config content never enters command text or history
(`src/sessions.zig:1323-1365`). Add a backup-specific queued outcome like the
nonblocking access operation (`src/sessions.zig:2016-2027`) rather than calling
handler-side waits.

### Provider adapters and rclone command construction

A provider adapter owns:

- product ID and rclone `provider` value
- required/optional/fixed endpoint and region fields
- whether AWS runtime/IAM is allowed
- exact storage classes exposed by that provider; empty means default
- config additions such as `env_auth = true` or R2 `region = auto`
- endpoint security policy and UI help

Minimum mappings:

- `aws` → `provider = AWS`; runtime/IAM allowed; region required; endpoint
  optional; official AWS class allow-list
- `r2` → `provider = Cloudflare`; endpoint required; region fixed to `auto`;
  runtime/IAM disabled; default class only
- `b2_s3` → `provider = Other`; S3-compatible endpoint required; runtime/IAM
  disabled; default class only
- `wasabi` → `provider = Wasabi`; tested endpoint/region pair; default class
  unless the adapter has direct documented and integration evidence
- `minio` → `provider = Minio`; endpoint required; explicit region when the
  target requires it; default class only
- `spaces` → `provider = DigitalOcean`; endpoint required; runtime/IAM disabled;
  default class only

Generated commands use fixed executable/subcommand/flag tokens. Every source,
config path, remote destination, state path, process identifier path, and other
variable shell word passes through `shellquote.quote`
(`src/shellquote.zig:1-48`). Secrets never become argv, environment values,
remote names, file names, audit details, or history commands.

Use:

```text
rclone copy|sync <quoted-source> <quoted-remote> --config <quoted-config>
  --use-json-log --stats 1s --stats-log-level NOTICE --ask-password=false
```

Do not parse the human progress line. Do not use `--error-on-no-transfer`.
Capture rclone path/version during refresh and freeze the absolute path in a
mutation plan so cron does not depend on a restricted `PATH`.

### Manual run and hard cancellation

Preparation is an explicit state machine:

1. verify job revision/server ownership and one active manual run per server
2. verify rclone capability and readable source (`missing` and `denied` differ)
3. create a random per-run remote state directory mode 0700
4. upload a unique config mode 0600; IAM config contains `env_auth = true` and
   no keys
5. start a generated run wrapper in a new, probed process group and capture its
   group identity before reporting `running`
6. stream JSON logs through the session stream; parse snapshots in coordinator
7. finalize from EOF/exit independent of frontend polling
8. terminate/verify on cancel; remove temp config/state; append atomic history;
   audit terminal result

The process group and cleanup paths are generated from random validated IDs,
not user text. If process-group setup is unavailable on a target, manual run is
blocked with `unsupported_target`; do not offer unverifiable cancellation.

### Scheduled wrapper and staging protocol

Resolve the connected user’s absolute home once. Store Oars-owned schedule
artifacts under:

```text
<home>/.config/oars/rclone.conf                    mode 0600
<home>/.local/state/oars/backups/<job-id>/run.sh  mode 0700
<home>/.local/state/oars/backups/<job-id>/meta.json mode 0600
<home>/.local/state/oars/backups/<job-id>/runs/    mode 0700
```

`meta.json` is versioned and contains no secret: job ID/revision, schedule,
normalized source/destination label, config section name, wrapper hash,
crontab-block hash, next due epoch, and retention limits.

The wrapper:

- uses only fixed code plus prequoted frozen values
- obtains an atomic per-job lock; overlap writes a terminal `skipped_overlap`
  status instead of disappearing
- applies interval `next_due_epoch` gating or the custom cron expression
- verifies the source immediately before rclone
- runs the absolute rclone binary with JSON logs and bounded built-in log
  rotation
- writes a numeric, versioned status record with run ID, job revision, UTC epoch
  times, exit code, status, cleanup state, and summary
- publishes status via sibling temporary file + sync + rename only after the log
  is closed
- prunes to at most 20 staged terminal runs and bounded log bytes without
  deleting an unimported active record
- never includes credentials in status/log output

Refresh imports with SFTP/stat/read operations, not `ls`, `cat`, or `rm` shell
strings. Validate names, versions, job/server/revision binding, file sizes, and
JSON before append. Append local history idempotently, then remove the exact
staged pair and verify absence. Unknown/corrupt/too-large records remain visible
as warnings and are not executed or silently deleted.

### Crontab mutation

A schedule plan freezes:

- current crontab bytes and SHA-256
- exact existing marker block, if any
- exact replacement block
- server timezone and implementation capability

Commit re-reads and compares the SHA-256. On match, replace/remove exactly one
marker block, validate, install bytes via stdin, then read back and compare the
expected block. On mismatch, return `conflict` without merging unseen edits.
No command contains crontab content. Saving an existing marker updates it;
`crontabAdd`’s current marker-present no-op is insufficient
(`src/backup.zig:370-387`).

### Local stores

Keep jobs and run history secret-free. Add schema versions and migrations.
Write both stores with sibling temp, mode 0600, file sync, atomic rename, and
parent-directory sync where available. Preserve quarantine behavior and return
the quarantined path as `recovery_error`.

Do not store capability-test sentinel contents, credentials, raw config, process
secret input, or full bridge payloads. Run summaries store normalized stats and
at most 200 KiB of secret-scrubbed log. List responses omit logs.

## Secret, mutation, quoting, and bounds requirements

### Secrets

- Keychain service remains `dev.native_sdk.oars`; account is
  `backup:<job_id>`.
- Store one versioned JSON string containing access and secret key. It never
  appears in `backups.json`, `backup_runs.json`, preview fixtures, audit,
  command history, error details, analytics, or console output.
- Add backup-specific `set`, transient `get`, and delete methods that bypass
  `secretCache`. Do not call the generic cached `vault.get`/`set` path.
- Secret inputs exist only while the create/test/run dialog requires them.
  Clear React state on success, cancel, server change, tab change, and unmount.
- Copy request secrets into owned mutable Zig buffers, validate, use, securely
  zero, then free on every path. Register backup credential payloads as
  sensitive in bridge diagnostics. The immutable framework request buffer must
  never be logged.
- Access/secret keys are each non-empty in access-key mode, at most 4 KiB, and
  reject NUL/CR/LF to prevent INI injection. IAM mode rejects supplied keys.
- Temporary configs are random, mode 0600, verified after write, and removed on
  every terminal path. Cleanup failure is explicit.
- Scheduled configs are an approved remote secret copy. Show that rclone
  obscuring is reversible and not encryption
  (<https://rclone.org/commands/rclone_obscure/>). IAM avoids this copy.

### Mutation and audit

- Test, Run now, schedule enable/change/disable, install/start, cleanup, and
  delete are approval-gated.
- Sync run/schedule and job deletion require exact-name confirmation.
- Every mutation takes an `operation_id`; retrying it returns the retained
  operation and never repeats remote work.
- Audit admission once and terminal outcome once. Include server/job/run IDs,
  plan hash, operation kind, and secret-free result. Imported scheduled runs
  produce one imported-result audit row.
- Record executed remote commands through tracked history with a redacted
  semantic command when paths should not be exposed. Never pass secret values
  into history merely to mask an unsafe command; keep them out of the command.

### Exact bounds

Enforce at bridge admission and in deserialization:

- server/job/operation/plan/run ID: 1–128 bytes; generated job/run IDs are
  random and path-safe
- job name: 1–80 Unicode bytes after trim; no controls
- source path: 1–1024 bytes, absolute POSIX path, no NUL/CR/LF
- bucket: 1–255 bytes; provider adapter validation
- prefix: 0–512 bytes; no NUL/CR/LF; normalize leading/trailing `/` once
- endpoint: 0–512 bytes; adapter-owned requirement; HTTPS by default. Plain HTTP
  requires an explicit insecure-endpoint approval and is allowed only for a
  user-entered private/test adapter such as MinIO
- region/storage class: 0–64 bytes and adapter allow-list
- custom cron expression: 1–128 ASCII bytes, exactly five fields in the
  supported grammar
- interval: 1–168 hours or 1–365 days
- credentials: 1–4096 bytes each, no NUL/CR/LF
- jobs: at most 128 per server
- retained plans: 32; retained operations: 64; active records never evicted
- one active mutating backup operation and one active manual run per server;
  status refresh coalesces
- short remote outcome: 256 KiB; live stream uses the existing 4 MiB retained
  stream cap (`src/sessions.zig:81-120`)
- local history: 200 records total, 90 days, 200 KiB log each
- staged scheduled records: 20 per job, at most 1 MiB log each
- poll delta: 256 KiB; history-log delta: 64 KiB; history list: 20 summaries

Oversize input is `invalid_payload`; oversize remote data is typed
`source_too_large`/`cleanup_failed` as appropriate, never truncated into a
false success.

## Frontend implementation

Create a typed feature controller rather than expanding the current component:

```text
frontend/src/backup-state.ts
frontend/src/backup-state.test.ts
frontend/src/BackupsTab.integration.test.tsx
```

`BackupsTab` may be split into `frontend/src/features/backups/` components and
hooks if useful. Keep one controller with:

- local jobs/status/history state
- one refresh-operation poller
- one active mutation-operation poller
- one active run poller with a caller-owned log cursor
- abort/generation guards so stale responses from a former `serverId` cannot
  overwrite current state
- timer cleanup on server/tab change and unmount
- last-good-state preservation on refresh/poll failure
- no `any`, legacy `paths`, `retention_days`, response aliases, or swallowed
  catch blocks

Use `docs/DESIGN.md`:

- one obvious primary action, **Create job**
- status text plus icon/dot; never color alone
- human labels (`Last backup`, `Needs attention`, `No changes`)
- restrained runtime attention area instead of raw JSON/toasts
- technical paths/IDs/logs in Geist Mono only
- dialogs with title, one-sentence consequence, affected server/job/path, and
  primary/cancel actions
- responsive rows/dialogs with no hidden destructive consequence, credential
  disclosure, or cancel action
- 150–220 ms restrained motion and reduced-motion compliance

The Protection workspace currently pairs Vault and the first server’s backups
in a fixed two-column layout (`frontend/src/App.tsx:1279-1293`). Make server
selection explicit there and stack at narrow widths; do not silently operate on
`servers[0]`.

## Deterministic preview fixtures

Add `backupsMode` beside the existing mode query parameters in
`frontend/preview.html:13-30`. Implement every `oars.backup.*` command above,
record payloads in `calls`, use fixed IDs/timestamps/paths, and make polling
advance by deterministic call count rather than wall-clock races.

Required `?backups=` fixtures:

- `populated` — Copy and Sync jobs with successful/no-change history
- `empty`
- `refreshing` — last-good jobs/status remain visible
- `disconnected` — stale jobs/history and blocked remote actions
- `rclone-missing`
- `cron-stopped`
- `partial-import` — corrupt/too-large staged record warning
- `editor-aws-key`
- `editor-aws-iam`
- `editor-r2`
- `editor-minio-http-warning`
- `test-plan`
- `test-running`
- `test-cleanup-failed` — exact leftover object path
- `schedule-secret-disclosure`
- `schedule-conflict`
- `run-copy`
- `run-sync-confirm`
- `run-no-changes`
- `run-failed`
- `run-cancel-requested`
- `run-interrupted`
- `delete-partial-cleanup`
- `install-plan`
- `unsupported-target`

Inspect each relevant fixture at desktop and narrow widths. Verify no console
errors, clipped dialogs, document-level overflow, hidden actions, status by
color alone, or secret values in recorded preview calls after dialog cleanup.

## Required tests

### Zig unit tests

Add or correct tests for:

- random ID uniqueness across registry reload and persisted-ID collision checks
- immutable server ownership and optimistic job revision conflicts
- provider adapter matrix and golden config for all six providers
- AWS runtime config emits `env_auth = true` and no key fields
- B2 S3 emits `provider = Other`; R2 emits `Cloudflare` + `region = auto`
- unsupported/default storage class omission
- credential CR/LF/NUL rejection and secure-zero paths
- exact cron grammar including lists, wildcard steps, range steps, invalid
  bounds, duplicate fields, tabs, `%`, and final newline
- interval due-time arithmetic without calendar-field drift
- crontab block insert/update/remove, duplicate-marker conflict, whole-table
  hash conflict, and unrelated-byte preservation
- versioned wrapper golden output: absolute rclone, source check, JSON stats,
  lock result, numeric atomic status, retention, and no secrets
- status parser with numeric fields, wrong version/job/revision, partial file,
  too-large log, malformed JSON, and unknown files
- rclone nested stats including `totalTransfers`, zero-transfer success, error
  lines, malformed lines, and partial line boundaries across stream chunks
- atomic jobs/history save, quarantine, schema migration, retention, and
  secret-absence scans
- operation idempotency, limits, expiry, cancellation states, disconnect, and
  cleanup-failed retention
- caller-owned log cursors with two independent consumers and dropped gaps

### Container integration

Extend `src/integration_backup.zig` and the Alpine/MinIO harness to prove:

- bridge handlers return promptly while a deliberately delayed remote backup
  operation continues on workers
- create plan → real list/write/**content read**/delete/absence test → save
- sentinel cleanup after failures at every post-write step; forced cleanup
  failure reports the exact leftover
- secret material is absent from bridge responses, jobs/history JSON, command
  history, audit, process argv, logs, status, and preview artifacts
- temporary config mode 0600 and removal after success, failure, cancellation,
  timeout, disconnect reconciliation, and coordinator shutdown
- copy leaves a destination-only object; sync deletes it only after typed
  confirmation
- full run, incremental run, unchanged run, existing empty directory, missing
  source, and unreadable source as distinct outcomes
- hard cancellation: TERM reaches the active process group, KILL follows after
  the bounded grace period, the operation reaches one terminal state, and the
  temporary config and sentinel are removed
- disconnect and coordinator shutdown use the same bounded cancellation and
  cleanup path rather than leaving rclone, SFTP work, or secrets behind
- crontab install/readback/remove under a real cron implementation, including
  hash conflict detection and byte-for-byte preservation of unrelated entries
- a real scheduled run while Oars is disconnected, followed by reconnect and
  import of the exact numeric status and retained JSON log
- overlap produces the documented busy/skipped status and does not overwrite a
  still-running attempt's staged files
- malformed, partial, stale-revision, oversized, and unknown staged records are
  quarantined or reported without blocking valid imports
- AWS IAM mode succeeds only through the remote process environment and never
  writes credential fields to the generated config
- install-plan detection remains read-only; an unsupported or unverified target
  returns the manual-fallback contract rather than executing guessed package
  manager commands
- every admitted mutation and every terminal operation result writes exactly
  one audit event, including conflict, cancellation, interruption, timeout, and
  cleanup failure

The current integration entry point is `src/integration_backup.zig:1-209`,
registered by `src/integration.zig:15-19`. Extend the existing container rather
than replacing its SSH/MinIO assertions. The current harness installs rclone in
`scripts/dev-sshd/Dockerfile:1-45` and runs the Zig integration executable from
`scripts/integration-test.sh:1-142`; add cron coverage explicitly and make a
missing daemon/tool an asserted skip or failure, never an accidental pass.

### Frontend contract, state, and component tests

Replace the legacy mock surface and add tests at the narrowest owning layer:

- `frontend/src/bridge.test.ts`: exact method names and payload envelopes for
  plan, test, save, delete, run, cancel, operation polling, log reads, history,
  schedule diagnostics, and install planning; reject the old flat Test payload
- `frontend/src/types.test.ts` or compile-time fixtures: every bridge response
  uses the discriminated unions and millisecond timestamp strings/numbers
  defined in this guide; no `any`, guessed optional field, or nanosecond JS
  number is accepted
- the backup state tests: preserve last-good jobs/history during refresh and
  recoverable errors, keep list/history/log cursors independent, deduplicate
  terminal reconciliation, ignore stale poll responses, and stop all timers on
  unmount, server switch, disconnect, and terminal completion
- Keychain tests: secrets enter the draft only from an explicit reveal, are
  cleared after plan/test/save/cancel/unmount, never enter generic bridge caches
  or persisted app state, and a missing/locked key produces a typed prompt
- `frontend/src/BackupsTab.test.tsx`: provider-specific fields and defaults,
  IAM-versus-key modes, HTTP endpoint warning, plan-before-save review, changed
  plan invalidation, content-read test progress, exact cleanup-failure path,
  Copy versus typed Sync confirmation, cancellation phases, stale/partial
  import warnings, destructive delete confirmation, and conflict recovery
- app-level tests around `frontend/src/App.tsx:1279-1293`: explicit server
  selection, no implicit `servers[0]`, disconnected behavior, and independent
  Vault/Backups loading and error boundaries
- accessibility assertions: focus return, Escape only when safe, labelled
  progress, live status text without color-only meaning, keyboard-reachable
  confirmations, and narrow-width dialogs without document overflow
- deterministic preview tests: every `?backups=` fixture listed above resolves
  without live time/network dependencies and records no secret-bearing payload

The existing backup assertions in
`frontend/src/modal-a11y-challenge.test.tsx:899-924` cover only modal focus and
Escape behavior. Keep those assertions, but do not treat them as bridge,
workflow, cancellation, or responsive coverage. The implementation is complete
only when tests use the production types from `frontend/src/types.ts`, not
parallel permissive mock shapes.

## Exact validation commands

Run from the repository root after implementation. The first command formats
exactly the changed Zig files discovered by Git; if there are no changed Zig
files, omit it rather than invoking `zig fmt` with an empty argument list.

```sh
git diff --name-only --diff-filter=ACMR -- '*.zig' | xargs zig fmt --check
zig build test
scripts/integration-test.sh
npm --prefix frontend test
npm --prefix frontend run build
frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit
git diff --check
```

Also run the deterministic preview matrix manually at desktop and narrow widths,
including at least `populated`, `editor-aws-key`, `test-running`,
`test-cleanup-failed`, `schedule-secret-disclosure`, `schedule-conflict`,
`run-sync-confirm`, `run-cancel-requested`, `partial-import`, and
`unsupported-target`. Record the tested browser, viewport sizes, and result in
the implementation PR.

These are implementation validation requirements, not observations about the
2026-08-21 baseline. This guide was produced from source inspection; it does not
claim that any command above currently passes.

## Acceptance gates

Spec 10 is releasable only when all of the following are true:

1. **Contracts agree.** `src/bridge.zig`, `src/backup.zig`, frontend bridge
   methods, production TypeScript types, mocks, tests, and deterministic
   previews implement the same versioned request/response/error contracts in
   this guide. There are no legacy fields or `any` escape hatches in the backup
   path.
2. **The runtime remains responsive.** No backup bridge handler performs
   `execWait`, SFTP waits, filesystem persistence, staged import, or rclone work
   on the runtime main thread. Admission is bounded; workers own blocking work;
   coordinator messages own published state.
3. **Secrets have one controlled lifetime.** Key material comes from Keychain
   only for the admitted operation, is passed through a mode-0600 temporary
   config rather than argv/environment/JSON, is zeroed and removed on every
   terminal path, and is absent from all enumerated persistence and telemetry
   surfaces. AWS IAM mode emits `env_auth = true` and no static credentials.
4. **Testing proves actual access.** Test Connection lists, writes a unique
   sentinel, reads its exact content with `rclone cat`, removes it, and verifies
   absence. A failed cleanup returns the exact leftover object and blocks Save.
5. **Mutations are transactional and conflict-safe.** Save/delete use plan,
   expected revision, crontab whole-table hash/readback, atomic local
   persistence, rollback/reconciliation, immutable server ownership, and
   exactly-once audit outcomes. Restart cannot reuse an existing ID.
6. **Scheduling works without Oars.** A real cron invocation completes while
   the app is closed/disconnected; reconnect imports the versioned numeric
   status and bounded JSON log exactly once. Unrelated crontab bytes survive,
   secrets never enter cron, interval gating honors elapsed intervals, and
   overlap is explicit.
7. **Cancellation and cleanup are hard guarantees.** Cancel/timeout/disconnect
   signal the process group, escalate after a bound, finalize without frontend
   polling, retain cleanup-failed evidence, and release worker/operation slots
   exactly once.
8. **Copy and Sync are truthful.** Copy preserves destination-only data; Sync
   can delete it and therefore requires the typed destructive confirmation.
   Full, incremental, unchanged, empty, missing, unreadable, cancelled,
   interrupted, and failed outcomes are distinguishable.
9. **Bounds and parsing are enforced.** Request sizes, identifiers, paths,
   schedule grammar, stream lines, logs, histories, staged records, operation
   counts, and retention are bounded before allocation or execution. Remote
   text is data, never shell syntax; quoting is centralized and `%`, CR/LF,
   NUL, control bytes, traversal, and marker injection are rejected where
   specified.
10. **The UI exposes real state.** Explicit server selection, stale-state
    preservation, operation phases, independent cursors, typed errors, cleanup
    actions, schedule diagnostics, installation fallback, responsive layouts,
    and accessible keyboard/focus/status behavior all have component tests and
    deterministic fixtures.
11. **Validation passes.** Every command in the validation section passes, the
    preview matrix is inspected, and the container test includes the closed-Oars
    scheduled-run/import scenario. Any platform adapter not exercised is
    reported as unsupported/manual, not inferred working.
12. **Documentation agrees.** On completion, update the Spec 10 status and any
    affected design/spec text in the implementation change so they describe the
    shipped contracts rather than the 2026-08-21 baseline.

## Non-goals

Do not expand this implementation into:

- restore workflows or disaster-recovery orchestration
- retention-policy management of user backup objects
- database-native snapshots, dumps, or application-consistent quiescing
- destinations beyond the six S3-compatible v1 adapters in this guide
- cloud account creation, IAM policy brokerage, credential rotation, or a new
  cross-platform secret manager
- a long-running rclone RC service or exposing rclone's remote-control API
- arbitrary user-authored rclone flags, shell snippets, cron expressions, or
  destination paths
- a broad scheduler abstraction beyond the explicitly tested cron adapters;
  unsupported systems receive diagnostics and a manual fallback
- redesign of unrelated Vault, server, or session workflows

## Primary-source references

Repository observations above are fixed to commit `bc2aa83` on 2026-08-21 and
cite the owning paths/symbols/line ranges inline. External behavior must be
implemented against these official primary sources:

- rclone S3 backend/provider options, credential modes, endpoints, and storage
  classes: <https://rclone.org/s3/>
- rclone global logging, including JSON log output:
  <https://rclone.org/docs/#logging>
- rclone process exit-code meanings:
  <https://rclone.org/docs/#exit-code>
- `rclone copy` source/destination and non-deletion semantics:
  <https://rclone.org/commands/rclone_copy/>
- `rclone sync` destination-matching and deletion semantics:
  <https://rclone.org/commands/rclone_sync/>
- rclone config-file discovery and override behavior:
  <https://rclone.org/commands/rclone_config_file/>
- rclone `obscure` warning: obscuring is reversible and is not encryption:
  <https://rclone.org/commands/rclone_obscure/>
- Cronie `crontab(1)` install/list/remove interface and temporary-file behavior:
  <https://github.com/cronie-crond/cronie/blob/master/man/crontab.1>
- Cronie `crontab(5)` grammar, step semantics, environment, and `%` handling:
  <https://github.com/cronie-crond/cronie/blob/master/man/crontab.5>

Do not generalize from one distro's package manager, daemon name, crontab path,
or service manager. Verify any added platform adapter against that platform's
official documentation and exercise it in the integration matrix before calling
it supported.
