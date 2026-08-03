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
  2. Provider (S3): AWS S3, Cloudflare R2 (+endpoint), Backblaze B2, Wasabi (+endpoint), MinIO (+endpoint), DigitalOcean Spaces (+endpoint) · bucket · region (where applicable) · access key / secret key (Keychain) **or** Use IAM Role · storage class (Standard/Glacier/Deep Archive).
  3. Schedule: Manual / Interval (every N hours/days) / Custom cron expression · timezone notice (server TZ).
  4. Test Connection (rclone lsd) → green check before save.
- **Run view:** progress card (size transferred, files transferred, speed, ETA, elapsed) + live log lines; per-run record with status.
- History: last 20 runs per job; View Log opens the raw output.

### 4.2 Local destination (Oars+)
- Destination = pick a local folder (native dialog); transfer = rclone copy **to local**? rclone works locally too (`rclone copy remote:... local:` or plain `cp -a`-style): v1 implementation = stream via SFTP download to the local folder with the same progress UI (reuse spec 05 transfer machinery) — no rclone required for local jobs.

## 5. Bridge API

### `oars.backup.jobs.list` `{server_id}` → `{ok, jobs}`
### `oars.backup.jobs.save` `{job}` → `{ok, job}` · `oars.backup.jobs.delete` `{server_id, job_id}` → `{ok}`
Job model:
```json
{"id":"b1…","server_id":"s1…","name":"daily-website","source_path":"/var/www/html",
 "destination":{"type":"s3","provider":"aws","bucket":"acme-backups","endpoint":"",
                "region":"us-east-1","use_iam":false,"storage_class":"standard"},
 "transfer":"sync","schedule":{"mode":"custom","expr":"0 2 * * *","enabled":true},
 "created_at":…,"updated_at":…}
```
- Secret keys (access/secret) live in Keychain under `backup:<job_id>`; never in JSON.
### `oars.backup.test` `{job}` → `{ok, ok:bool, error?}` (rclone lsd)
### `oars.backup.run` `{server_id, job_id}` → `{ok, run_id}`
### `oars.backup.poll` `{run_id}` → `{ok, status, bytes_done, bytes_total, files_done, files_total, speed_bps, eta_sec, log_delta, error?}`
- Progress parsed from rclone's `--progress`/`--stats-one-line` output (structured enough: `Transferred: 1.2 GiB / 2.3 GiB, 47%, 5.2 MB/s, ETA 4m`).
### `oars.backup.history` `{server_id, job_id, limit}` → `{ok, runs}` (persisted locally, not on server)
### `oars.backup.install` `{server_id, what: rclone|cron}` → `{ok}` (exec install; approval-gated; audit)
### `oars.backup.cronStatus` `{server_id}` → `{ok, rclone: bool, cron_installed: bool, cron_running: bool}`

## 6. Zig core design

- `src/backup.zig` — Job model + store (`<data>/backups.json`), rclone config generation (INI written via SFTP to `~/.config/rclone/rclone.conf` — append/merge section), crontab management (read `crontab -l`, add/remove line by job id marker `# oars:job:<id>`, write back via `crontab -`), run state machine (exec `rclone <transfer> <src> <dst> --progress --stats-one-line` on a channel; parse stats; per-run record), install helpers.
- Local-destination jobs bypass rclone: SFTP download stream (spec 05 machinery) with progress.
- Command construction is argv-based (rclone flags; paths validated); user paths are single argv elements.

## 7. Data model

- `<data>/backups.json`: jobs (no secrets). `<data>/backup_runs.json`: run history (status, stats, trimmed log 200 KB, kept 90 days).
- Server-side: rclone.conf section per job; crontab lines with id markers.

## 8. Security

- Bucket credentials → Keychain; IAM-role option avoids storing any.
- rclone.conf on the server contains credentials (it must) — chmod 600 enforced; documented.
- Mutations (install, run, delete job) approval-gated; run history audited.
- The "copied nothing but said Success" trap is handled in UI: zero-file runs render an explicit amber "0 files — check source path" state, not a green Success.

## 9. Performance

- Progress polling rides the channel stream (no extra threads); ETA math client-side.
- Large fleets: one backup job per server; jobs run server-side so the app only watches.

## 10. Edge cases

- Source path typo → 0 files transferred → amber warning + hint (see §8).
- rclone missing → banner + one-click install; manual runs blocked until installed.
- cron missing/stopped → banner; interval/custom schedules disabled in the form until fixed.
- Server timezone mismatch → schedule note in form + actual crontab shows server TZ; run history timestamps normalized to UTC + local display.
- Bucket permission error → test catches pre-save; run errors surface the exact rclone line.
- Disk fills locally during a local-destination job → job fails with clear message, partial files cleaned.

## 11. Testing

- Unit: rclone INI generation, crontab line add/remove (round-trip fixtures), stats-line parser (various units: B/KiB/MiB/GiB, comma formats), zero-file detection.
- Integration (container + MinIO via docker): test connection, run sync job, verify objects in bucket, second run with changed file, broken source path → zero-file warning, history entries.
- Manual: schedule writes crontab (verify with `crontab -l`), timezone notice, local-destination job.

## 12. Acceptance criteria

- [ ] S3 job (MinIO in tests) runs and lands objects; progress + log correct.
- [ ] Test Connection catches bad credentials before save.
- [ ] Crontab entries are idempotent (re-save doesn't duplicate).
- [ ] Zero-file runs are visually distinguished from success.
- [ ] Secrets never appear in JSON, logs, or audit.
