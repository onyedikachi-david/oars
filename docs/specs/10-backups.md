# Spec 10 — Backups

**Status:** 📋 · **Depends on:** 02 (exec/follow) · **Spec owner:** core

## 1. Overview

Scheduled copies of any folder to S3-compatible storage: fill one form,
test the connection, and the rclone config and crontab are written for
you. Every run keeps a log with file counts — a backup you can prove.

## 2. Goals / non-goals

**Goals**
- Job model: source path, provider, bucket, credentials (or IAM), sync/copy, storage class, schedule (manual/interval/custom cron).
- Test Connection before save; one-click install of rclone and cron when missing.
- Run now, or scheduled via crontab written by Oars; live progress (bytes, files, speed, ETA); per-run logs.
- (Oars+ — beyond CtrlOps) optional **local destination** (copy to a local folder on the user's machine) alongside S3.

**Non-goals**
- No restore (documented; restore = provider console or rclone reverse), no retention/rotation policy (sync mirrors; lifecycle rules live in the bucket), no DB-aware snapshots (documented: dump first), no destinations beyond S3-compatible (+ local Oars+).

## 3. User stories

- I create `daily-website` pointing at `/var/www/html` → `s3://acme-backups`; connection tested before I save.
- At 2 AM the crontab fires it; I open the app and see "1,284/1,284 files · 2.3 GB · Success".
- A run fails; View Log shows the exact rclone error and I hand it to the AI terminal.
- (Oars+) I back up a folder to my own machine when there's no bucket.

## 4. UI/UX

### 4.1 Backups view (per server)
- Status strip: rclone installed? cron running? (banner + one-click install/start).
- Job list: name · source → destination · schedule · last run (Success/Failed · files · size · duration) · actions (Run now, Edit, Delete, View Log).
- **Create Job** form:
  1. Basic: job name · source path · destination type (S3-compatible / Local folder) · transfer type (Sync mirrors / Copy adds).
  2. Provider (S3): AWS S3, Cloudflare R2 (+endpoint), Backblaze B2, Wasabi (+endpoint), MinIO (+endpoint), DigitalOcean Spaces (+endpoint) · bucket · region (where applicable) · access key / secret key (Keychain) **or** Use IAM Role · only storage classes supported by the selected backend adapter.
  3. Schedule: Manual / Interval (every N hours/days) / Custom cron expression · timezone notice (server TZ).
  4. Test Connection → preview the exact bucket/prefix capability test, run it
     after approval, and show list/write/read/delete results before save.
- **Run view:** progress card (size transferred, files transferred, speed, ETA, elapsed) + live log lines; per-run record with status.
- History: last 20 runs per job; View Log opens the raw output.

### 4.2 Local destination (Oars+)
- Destination = pick a local folder (native dialog); transfer = rclone copy **to local**? rclone works locally too (`rclone copy remote:... local:` or plain `cp -a`-style): v1 implementation = stream via SFTP download to the local folder with the same progress UI (reuse spec 05 transfer machinery) — no rclone required for local jobs.
- Local-destination jobs are manual while Oars is open. A server cron job
  cannot write to a folder on a laptop that can be asleep or disconnected.

## 5. Bridge API

### `oars.backup.jobs.list` `{server_id}` → `{ok, jobs}`
### `oars.backup.jobs.save` `{job, schedule_credentials?}` → `{ok, job}` · `oars.backup.jobs.delete` `{server_id, job_id}` → `{ok}`
Job model:
```json
{"id":"b1…","server_id":"s1…","name":"daily-website","source_path":"/var/www/html",
 "destination":{"type":"s3","provider":"aws","bucket":"acme-backups","endpoint":"",
                "region":"us-east-1","use_iam":false,"storage_class":"standard"},
 "transfer":"sync","schedule":{"mode":"custom","expr":"0 2 * * *","enabled":true},
 "created_at":…,"updated_at":…}
```
- Secret keys (access/secret) live in Keychain under `backup:<job_id>`; never in JSON.
  `schedule_credentials` is accepted only when enabling an unattended
  non-IAM schedule, after the remote-secret disclosure.
### `oars.backup.test` `{job, credentials?}` → `{ok, ok:bool, error?}`
- Test the exact bucket and prefix, not only the remote root. After a clear
  mutation notice, create a unique small sentinel object, read/stat it, and
  delete it. A Copy job requires list, write, read/stat, and sentinel cleanup.
  A Sync job must also prove destination delete authority. If cleanup fails,
  report the leftover object path prominently and do not mark the test passed.
### `oars.backup.run` `{server_id, job_id, credentials?}` → `{ok, run_id}`
- The frontend reads the job's Keychain entry only for Test, a manual run, or
  schedule installation. Tests and manual runs use a unique remote temporary
  config with mode 0600 and delete it after completion. IAM mode sends no
  credentials.
### `oars.backup.poll` `{run_id, log_cursor?}` → `{ok, status, bytes_done, bytes_total, files_done, files_total, speed_bps, eta_sec, log_cursor, log_delta, dropped, error?}`
- Run rclone with JSON logs and parse structured stats fields. Human one-line
  output is for display and is not a stable machine protocol.
- `log_cursor` is caller-owned under spec 02. Progress counters are current
  snapshots; reading log deltas in one view cannot drain another.
### `oars.backup.history` `{server_id, job_id, limit}` → `{ok, runs}`
- Canonical history is local. Scheduled runs stage bounded status and log files
  on the server until Oars imports them on the next connection.
### `oars.backup.install` `{server_id, what: rclone|cron}` → `{ok}` (exec install; approval-gated; audit)
### `oars.backup.cronStatus` `{server_id}` → `{ok, rclone: bool, cron_installed: bool, cron_running: bool}`

## 6. Zig core design

- `src/backup.zig` — Job model + store (`<data>/backups.json`), a dedicated
  remote config file at `~/.config/oars/rclone.conf` only for enabled
  unattended schedules, crontab management with
  `# oars:job:<id>` markers, and a run state machine. Validate source existence
  before rclone. A successful run with zero transfers means "no changes" and
  remains success; an empty source can also be valid.
- Install helpers first detect the OS, architecture, package manager, service
  manager, and current package source. They show a tested adapter's exact
  download/package, checksum or repository change, service action, and
  privilege before approval. An unknown target gets manual instructions, not a
  guessed command.
- Use `--use-json-log` and a short stats interval. Do not use
  `--error-on-no-transfer`: rclone documents exit 9 as "successful, but no
  files transferred," which is normal for an unchanged backup.
- `crontab -T` is a Cronie extension and is not portable to every target. Use
  it when detected. Otherwise validate the supported five-field grammar in
  Oars, then install and read back the resulting crontab.
- A small generated remote wrapper writes one run log and a machine-readable
  status file per scheduled run under `~/.local/state/oars/backups/<job-id>/`.
  Cron calls that wrapper. On reconnect, Oars imports completed records into
  local history and applies retention. Without this remote status boundary, a
  run that happens while Oars is closed cannot appear truthfully in history.
- Local-destination jobs bypass rclone: SFTP download stream (spec 05 machinery) with progress.
- SSH exec still accepts one shell string. Rclone flags and paths use fixed
  templates plus the shared POSIX-shell quoting function.

## 7. Data model

- `<data>/backups.json`: jobs (no secrets). `<data>/backup_runs.json`: run history (status, stats, trimmed log 200 KB, kept 90 days).
- Server-side: dedicated rclone config, generated run wrapper, bounded status
  and log files, and crontab lines with id markers.

## 8. Security

- Bucket credentials → Keychain; IAM-role option avoids storing any.
- Scheduled S3 jobs copy credentials from Keychain into the dedicated remote
  rclone config because cron cannot read the local Keychain. Rclone obscuring
  is reversible and is not encryption. Show this disclosure before save and
  enforce mode 0600. IAM roles avoid this remote secret copy.
- Installs, Test Connection, Run now, and job deletion are approval-gated and
  audited. Enabling a schedule is the recorded advance approval for its future
  cron runs; each scheduled result is imported into audit history.
- Check source existence before each run. A successful zero-transfer run is
  shown as "No changes". Missing source and permission failures are errors.

## 9. Performance

- Progress polling rides the channel stream (no extra threads); ETA math client-side.
- A server can have multiple jobs. Limit concurrent manual runs per server and
  use a per-job lock in generated cron wrappers so the same job cannot overlap
  itself.

## 10. Edge cases

- Missing source path → fail before rclone. An existing empty directory is
  valid and can complete with no changes.
- rclone missing → banner + one-click install; manual runs blocked until installed.
- cron missing/stopped → banner; interval/custom schedules disabled in the form until fixed.
- Server timezone mismatch → schedule note in form + actual crontab shows server TZ; run history timestamps normalized to UTC + local display.
- Bucket permission error → test catches pre-save; run errors surface the exact rclone line.
- Disk fills locally during a local-destination job → job fails with clear message, partial files cleaned.

## 11. Testing

- Unit: rclone INI generation, crontab line add/remove (round-trip fixtures),
  JSON-log and numeric `stats` object parsing, and zero-transfer state.
- Integration (container + MinIO via docker): capability test and sentinel
  cleanup, run sync job, verify objects in bucket, second unchanged run, changed
  file, missing source failure, and history entries.
- Manual: schedule writes crontab (verify with `crontab -l`), timezone notice, local-destination job.

## 12. Acceptance criteria

- [x] S3 job (MinIO in tests) runs and lands objects; progress + log correct.
      (container integration: `src/integration_backup.zig` — sync run polled to
      success with 2 files, incremental run after a source edit, no-changes run,
      history records, and object-landing verification via `rclone lsf`.)
- [x] Test Connection proves the selected prefix permissions needed by Copy or
      Sync and removes its sentinel object. (real sentinel write/read/delete in
      the bucket, leftover verified absent; sync jobs additionally prove
      prefix-level delete authority.)
- [x] Crontab entries are idempotent (re-save doesn't duplicate). (unit:
      `crontabAdd`/`crontabRemove` round trip, marker `# oars:job:<id>`, and
      unchanged-content no-op; the live cron-daemon leg of the install path is
      not container-tested yet.)
- [ ] A scheduled run that completes while Oars is closed appears after the
      next connection with its real exit status and log. (import path
      `backupImportStaged` implemented — status/log staging under
      `~/.local/state/oars/backups/<job-id>/` — but needs a live cron run in
      the harness; pending next spec cycle.)
- [x] Unchanged and empty valid sources finish as "No changes"; missing or
      unreadable sources fail before transfer. (no-changes verified in the
      container; the pre-transfer `test -d || test -f` gate is handler-level.)
- [x] Secrets never appear in JSON, logs, or audit. (dispatcher test asserts
      access/secret key material is absent from `jobs.list`; run/test configs
      are unique temp files mode 0600, deleted after finalize; audit detail
      carries only job ids.)

Integration harness (spec 10): `scripts/dev-sshd.sh` now also starts an
`oars-dev-minio` container on the shared `oars-dev-net` network and exports
`OARS_TEST_MINIO_*`; the dev sshd image installs rclone. Run the full leg
with `scripts/integration-test.sh`.

Known rclone quirks handled (spec 13): `--use-json-log` writes to stderr, so
manual runs append `2>&1`; MinIO rejects the lowercase `storage_class`, so
configs emit the canonical uppercase S3 value.

## 13. Research & References

- **rclone semantics** — verified against official rclone docs
  (`https://rclone.org/docs/` and
  `https://rclone.org/commands/rclone_copy/`):
  - `copy` transfers files that differ (size + modtime, or MD5SUM)
    and never deletes destination extras; `sync` "make[s] source and
    dest identical, modifying destination only" — matches the
    Transfer-type choice in the job model.
  - `rclone lsd` lists directories/buckets, but success at the remote root does
    not prove write or delete authority in the selected prefix. The capability
    test in §5 uses real operations on one unique sentinel and requires cleanup.
  - `--use-json-log` emits JSON Lines. Current official docs state that stats
    records include a `stats` object with fields such as `bytes`, `checks`,
    `elapsedTime`, `eta`, `speed`, `totalBytes`, and `transfers`. Use
    `--stats <interval>` plus an enabled stats log level and parse that object;
    do not parse the human `--stats-one-line` string.
  - **Zero-file correction:** rclone says `--error-on-no-transfer` changes a
    normally successful no-change run into exit 9. That is not evidence of a
    bad source. The flag was removed; Oars checks the source first and treats
    zero transfers as a normal no-change result.
  - `--dry-run` for trial runs (used by Test Connection variants).
- **rclone config file** — documented format: basic INI at
  `~/.config/rclone/rclone.conf` (Unix), `[section]` header per remote,
  `key = value` entries, required `type` key, comments `;` or `#`,
  passwords stored in obscured form; the file "will typically contain
  login information, and should therefore have restricted permissions"
  (rclone writes temp+rename itself) — validates spec §8's chmod 600
  and the merge-section write strategy (append a new `[oars-<job_id>]`
  section; never rewrite other sections).
- **crontab** — verified against cronie crontab(1)/crontab(5) man pages
  (`https://man7.org/linux/man-pages/man1/crontab.1.html`,
  `https://man7.org/linux/man-pages/man5/crontab.5.html`):
  - `crontab -l` prints the current table to stdout; `crontab -`
    installs a new table from stdin (both used by the crontab
    management in §6).
  - Five time fields (minute 0–59, hour 0–23, day-of-month 1–31,
    month 1–12, day-of-week 0–7); `#` comments only at line start
    (our `# oars:job:<id>` marker lines are safe); commands run via
    `/bin/sh` or `$SHELL`; cron checks every minute; `%` in a command
    becomes newline (must escape `%` in rclone invocations — worth a
    parser test); the crontab file must end in a newline.
  - Cronie provides `crontab -T`, but this is not a portable crontab option.
    Oars must detect it and keep an internal validator for other cron
    implementations.
- **S3-compatible providers** — AWS S3, Cloudflare R2 (S3-compatible
  endpoint), Backblaze B2, Wasabi, MinIO, DigitalOcean Spaces are all
  rclone-supported backends (documented backend list,
  `https://rclone.org/docs/#configure`); endpoint+region semantics
  come from each backend's rclone docs page.
- **Storage classes** — storage-class names and support vary by S3 provider.
  Oars exposes only values defined by its tested backend adapter and passes the
  selected value through the backend's documented rclone option; it does not
  offer AWS Glacier names as universal S3 choices.

Sources: rclone docs (usage, copy, flags), cronie crontab(1)/(5),
rclone backend list.
