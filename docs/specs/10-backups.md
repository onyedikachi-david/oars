# Spec 10 — Backups

**Status:** ✅ v1 frontend + backend implemented · **Depends on:** 02 (exec/follow), 15 (audit) · **Spec owner:** core

> Verified on 2026-08-31 against the full working tree. The release evidence
> includes unit tests, the Alpine SSH and MinIO integration harness, a real
> disconnected cron run, TypeScript checks, the frontend suite, and desktop
> and narrow deterministic browser fixtures.

## 1. Overview

Oars copies a remote source path to S3-compatible storage. A user can test the
exact destination, save a manual or scheduled job, run it now, stop it, and
review durable progress and history. A scheduled job runs on the server when
Oars is closed and imports its result after the next connection.

## 2. Goals and non-goals

### Goals

- Support AWS S3, Cloudflare R2, Backblaze B2 S3, Wasabi, MinIO, and
  DigitalOcean Spaces through explicit provider adapters.
- Support `copy` and `sync`. Copy keeps destination-only objects. Sync removes
  them and requires exact job-name confirmation.
- Support manual, interval, and five-field custom cron schedules in the
  server time zone.
- Prove list, write, read, delete, and cleanup access on the exact bucket and
  prefix before save.
- Keep local credentials in Keychain. Copy credentials to a mode-0600 remote
  config only after explicit approval for an unattended schedule.
- Keep bridge admission fast. A bounded coordinator and the SSH session worker
  own all remote work.
- Keep durable job, operation, run, audit, and recovery evidence.

### Non-goals

- V1 does not restore data. The user restores with the provider console or a
  reverse rclone command.
- V1 does not make database snapshots. The user must create a consistent dump
  before Oars copies database files.
- V1 does not manage bucket lifecycle or version-retention rules.
- V1 does not support a local laptop destination. This remains an Oars+ idea
  and is outside the v1 contract.

## 3. User stories

- I can create `daily-website` for `/var/www/html`, test its exact S3 prefix,
  and save it only after the capability proof passes.
- I can choose Copy when I must keep objects that exist only at the
  destination, or Sync when I want the destination to match the source.
- I can run a job now, follow its log with an independent cursor, and stop the
  tracked remote process group.
- I can close Oars before a cron run and see the real result and bounded log
  after I reconnect.
- I can see the exact leftover path or object when cleanup needs recovery.

## 4. UI and interaction

The Backups view is scoped to the active server. It shows runtime readiness,
jobs, last-run state, history, and recovery warnings.

The editor includes:

1. **Source and destination.** The user enters the source path, provider,
   bucket, prefix, endpoint, region, storage class, and transfer behavior.
2. **Credentials.** AWS can use runtime credentials. Other adapters use an
   access key and secret key. Saved keys use `backup:<job_id>` in Keychain.
3. **Schedule.** Manual, interval, and custom cron modes show the server time
   zone and the exact generated schedule plan.
4. **Proof and approval.** The UI shows the sentinel mutation before Test. It
   shows remote secret placement before scheduled save. Sync and Delete use
   exact job-name confirmation.

Operation sheets show every plan step and its state. Run sheets show bytes,
files, speed, ETA, elapsed time, cleanup state, and cursor-based logs. Partial
operations keep the exact recovery action. A user can retry cleanup without
repeating the remote transfer or mutation.

The view has deterministic fixtures for populated, empty, disconnected,
runtime-missing, cron-stopped, editor, proof, save, copy, sync-confirmation,
no-change, failure, cancel, interrupted, partial-import, delete-recovery,
install, and unsupported-target states. The desktop and narrow layouts keep
all actions keyboard reachable and return focus after a sheet closes.

## 5. Bridge contract

All timestamps are integer epoch milliseconds. Every mutation uses a bounded
`operation_id`. A retry with the same ID refers to the same frozen work.
User-facing failures have a stable code, message, retry flag, and optional
step, path, or remote-object detail.

### Jobs and server state

```text
oars.backup.jobs.list {server_id}
oars.backup.jobs.plan {job}
oars.backup.jobs.save {
  operation_id, plan_id, capability_proof_id?,
  schedule_credentials?, approved_remote_secret, confirm_job_name?
}
oars.backup.jobs.deletePlan {server_id, job_id, expected_revision}
oars.backup.jobs.delete {operation_id, plan_id, confirm_job_name}
oars.backup.status {server_id}
oars.backup.refresh {operation_id, server_id}
```

A job has a stable random ID, immutable server ID, monotonic revision, source
path, typed S3 destination, `copy|sync` transfer, typed schedule, and optional
capability proof. Stored job JSON never contains credentials.

### Capability, install, and durable operations

```text
oars.backup.test.plan {job_plan_id}
oars.backup.test {operation_id, test_plan_id, credentials?}
oars.backup.install.plan {server_id, what}
oars.backup.install {operation_id, plan_id}
oars.backup.operationPoll {operation_id}
oars.backup.operationCancel {operation_id, credentials?}
```

Poll is observation only. It never advances remote work. `operationCancel`
stops admitted work or retries the exact cleanup for retained partial state.

### Manual runs and history

```text
oars.backup.run {
  operation_id, server_id, job_id, expected_revision,
  credentials?, confirm_job_name?
}
oars.backup.poll {run_id, log_cursor?}
oars.backup.cancel {run_id}
oars.backup.history {server_id, job_id, limit?}
oars.backup.historyLog {server_id, run_id, cursor?, max?}
```

Run states are `queued`, `preparing`, `running`, `cancel_requested`,
`success`, `no_changes`, `failed`, `canceled`, `interrupted`, `partial`, and
`skipped_overlap`. Each caller owns its absolute log cursor. `dropped` reports
an individual cursor gap.

## 6. Core design

`src/backup.zig` owns validation, adapters, plan hashes, stores, the bounded
coordinator, operation snapshots, run state, rclone JSON-log parsing, cron
generation, scheduled import, cancellation, and recovery. `src/bridge.zig`
only validates bounded input, admits work, and copies locked snapshots.

The coordinator uses the session worker through an asynchronous remote
adapter. No backup bridge handler calls a network wait, SFTP wait, sleep, or
libssh2 function. Admission remains responsive while a remote step is held.

Save and delete are planned mutations:

- Save freezes the job, revision, capability binding, schedule effects, remote
  secret decision, and plan hash. Remote prepare and read-back happen before
  the local commit.
- Delete freezes the job identity and exact effects. It removes and verifies
  scheduled artifacts before the local delete. A failed cleanup remains
  partial and retains the same operation ID.
- Audit admission must persist before a remote side effect. Completion audit
  must persist before a successful terminal state is exposed.

Manual runs create a unique mode-0600 rclone config in
`~/.local/state/oars/backups/.manual/<run-id>/`. The tracked command runs in a
new process group. Stop sends `TERM`, waits to a bound, sends `KILL` when
needed, and verifies that the process group is absent. Oars then removes and
verifies the config file, process-ID file, and empty state directory.

Scheduled jobs use a versioned server wrapper, a dedicated mode-0600 config,
a metadata file, a lock, and one crontab marker block. The wrapper writes a
bounded log and atomically publishes a paired status file. Source failures and
overlap also publish paired records. Oars imports only a valid pair, appends
history and audit first, and removes the pair only after both durable writes
succeed. Re-import is idempotent.

## 7. Persistence

- `backups.json` stores versioned jobs with no secrets.
- `backup_runs.json` stores bounded history and trimmed logs.
- `backup_operations.json` stores at most 64 versioned operation records. It
  stores identity, state, plan payload, remote sentinel, result, failure,
  cleanup, audit generation, and the plan hash. It stores no credentials.
- All local stores use bounded reads, quarantine invalid data, write a
  mode-0600 sibling temporary file, sync it, rename it, and sync the parent
  directory.
- Restart restores terminal operations. A non-terminal operation becomes
  partial and interrupted. Recovery can perform cleanup only; it does not
  repeat ambiguous remote work.

## 8. Security

- Access keys and secret keys use Keychain account `backup:<job_id>`. Edit uses
  a pending account until the backend commit succeeds. Delete and runtime-mode
  changes remove obsolete entries after the backend commit.
- The frontend clears credential fields after admission. Backend-owned copies
  are bounded, validated against NUL and line injection, and overwritten on
  all paths.
- Test and manual-run configs are unique, mode 0600, and removed with exact
  cleanup proof.
- A scheduled key must exist on the server because cron runs without Oars.
  The UI states this fact and requires approval. AWS runtime credentials avoid
  the remote key copy.
- Shell values use the shared POSIX quoting function. Credentials travel by
  worker-owned input and never appear in command text, JSON stores, logs, or
  audit details.
- Test, save, delete, install, run, cancel, scheduled results, and recovery
  have audit records with secret-free identifiers.

## 9. Bounds and performance

- A server can have at most 128 jobs and one live manual run.
- Operation storage keeps 64 records. Completed live runs keep a bounded ring.
- Local run history keeps 90 days. Stored and staged logs have fixed byte
  limits, and scheduled artifacts keep a bounded run count.
- Input strings, credentials, cron fields, JSON files, remote files, stream
  deltas, and operation results are bounded before allocation.
- Bridge admission is below 500 ms in the real container test. Remote work and
  polling do not block unrelated bridge commands.

## 10. Edge cases

- An unchanged or empty valid source is `no_changes`.
- A missing or unreadable source fails before rclone starts.
- A second scheduled run for the same job is `skipped_overlap`.
- Disconnect without verified process termination is `interrupted`.
- Cleanup failure is `partial` with the exact leftover path or object.
- Missing rclone, missing or stopped cron, unsupported OS, stale revision,
  expired plan, denied Keychain access, audit failure, corrupt local store,
  and invalid staged files each have a typed state.
- A valid status file without its paired log is not imported. Invalid or
  oversized pairs are quarantined or retained with a warning.

## 11. Verification

The Zig unit suite covers validation, all six provider config goldens,
schedule grammar and migration, wrapper output, JSON-log parsing, bounds,
atomic stores, audit gates, operation replay, cleanup recovery, cancellation,
and coordinator responsiveness.

The real Alpine SSH and MinIO test covers:

- the exact sentinel list, write, read, delete, and absence proof;
- initial, unchanged, incremental, empty, and missing-source manual runs;
- Copy preserving a destination-only object and Sync removing it;
- exact Sync confirmation;
- `TERM`-resistant process cancellation with `KILL` and absence proof;
- a cron run during a 70-second period with no live Oars manager or registry;
- import through a fresh manager and registry, exact-once re-import, and
  verified scheduled-job deletion.

The React suite covers typed reducers, Keychain states, plans, approvals,
progress, cursor logs, partial cleanup, import warnings, delete recovery,
focus, and responsive behavior. The deterministic preview covers the full
state matrix at desktop and narrow sizes.

## 12. Acceptance criteria

- [x] All bridge handlers return after local validation and admission. The
  coordinator and session worker own remote work.
- [x] All six provider adapters generate verified rclone configuration, and
  the exact selected prefix passes a real mutation and cleanup proof.
- [x] Job save and delete use frozen plans, revisions, idempotent operation
  IDs, durable audit gates, verified remote effects, and restart recovery.
- [x] Manual Stop uses process-group `TERM` and bounded `KILL`, proves absence,
  and reports exact cleanup state.
- [x] Keychain, transient secret, scheduled disclosure, mode-0600 remote
  secret, overwrite, and obsolete-entry cleanup flows work end to end.
- [x] Copy and Sync have distinct proven behavior. Unchanged and empty sources
  are `no_changes`; missing and unreadable sources fail before transfer.
- [x] A real scheduled run completes while Oars is closed and imports once
  through a fresh manager and registry with its status and log.
- [x] Local stores, remote staging, logs, histories, operations, queues, and
  inputs have tested bounds and recovery behavior.
- [x] The typed Backups UI, deterministic preview matrix, keyboard behavior,
  desktop layout, and narrow layout pass their release checks.
- [x] Zig format, Zig build and tests, container integration, frontend tests,
  TypeScript checks, frontend production build, and diff checks pass in the
  same working tree.

## 13. Research and references

- [rclone S3 backend](https://rclone.org/s3/) defines provider values,
  endpoint and region fields, runtime authentication, and storage classes.
- [rclone copy](https://rclone.org/commands/rclone_copy/) keeps files that
  exist only at the destination.
- [rclone sync](https://rclone.org/commands/rclone_sync/) changes the
  destination to match the source and can remove destination-only files.
- [rclone global flags](https://rclone.org/flags/) defines JSON logs and stats
  options. Oars parses structured JSON instead of human status text.
- [rclone exit codes](https://rclone.org/docs/#list-of-exit-codes) defines exit
  9 for `--error-on-no-transfer`. Oars does not use that flag because no
  transfer is a valid no-change result.
- [crontab(1)](https://man7.org/linux/man-pages/man1/crontab.1.html) defines
  list and install behavior. `crontab -T` is not portable, so Oars uses its own
  bounded grammar and uses target validation only when available.
- [crontab(5)](https://man7.org/linux/man-pages/man5/crontab.5.html) defines
  five-field time syntax, shell execution, comments, percent handling, and the
  one-minute scheduler interval used by the integration test.
