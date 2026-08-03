# Spec 06 — Scripts + Safe Broadcast

**Status:** 📋 · **Depends on:** 02 (exec), 01 · **Spec owner:** core + frontend

## 1. Overview

A personal library of shell commands with `{{variable}}` templating, run
with one click on the server you're looking at. **Oars+ differentiator:**
safe broadcast — run one script across a *selection* of servers with a
per-server dry-run summary and a single confirmed execution, side-by-side
streams. (CtrlOps explicitly refuses fan-out; we do it with guardrails.)

## 2. Goals / non-goals

**Goals**
- CRUD scripts: name, description, tags, color, body with `{{var}}` placeholders.
- Run on current server; run-time variable prompts; live output in a pane.
- Run counts + last-run stamps per script; search + tag filter.
- Safe broadcast: select servers → dry-run summary → confirm → parallel streams with per-server exit codes.
- Approve-then-save from the AI terminal (spec 11) and from history (spec 15).

**Non-goals**
- No scheduling (backups own cron), no server-side installation of scripts, no sharing.

## 3. User stories

- I save `tail-error-logs` once with `{{service}}`; I run it for nginx, then php-fpm.
- I tag destructive scripts red so they never look harmless.
- I apply a disk-cleanup script to 6 boxes after seeing the expanded command on each.

## 4. UI/UX

### 4.1 Scripts panel (accessible from a tab header action + ⌘K)
- Left: script list — color chip · name · tags · run count / last-run ("no runs yet").
- Search box filters name+description+tags.
- Editor (modal or right pane): name, description, tags, color picker (6 swatches), command textarea with `{{` autocomplete of known variables; live variable detection count ("1 line · 2 vars").
- Run flow: Run → variable prompt dialog (per var, prefilled with last value) → output pane streams (header: script name · server · exit code).

### 4.2 Safe broadcast flow
1. From a script: **Run on multiple servers…** → selection sheet (server list with checkboxes + groups).
2. Dry-run summary: for each server, the **expanded command** (variables substituted) — read-only preview.
3. Confirm ("Run on N servers") — scripts tagged destructive require an extra confirm ("These are marked destructive").
4. Execution: streams side-by-side (each server a column/row with its own output + status); per-server exit codes; summary line "6/6 succeeded" / "db-02 failed (exit 2)".
5. Cancel stops remaining queued servers (running ones finish or are killed via channel close).

### 4.3 States
- No scripts → empty state with "Save your first script" + example button (prefills `sudo tail -f /var/log/{{service}}/error.log`).
- Run failed → toast "Script failed, check terminal output" + real error visible in the pane (never rewritten).

## 5. Bridge API

### `oars.scripts.list` → `{ok, scripts}` · `oars.scripts.save` `{script}` → `{ok, script}` · `oars.scripts.delete` `{id}` → `{ok}`
### `oars.scripts.run` `{server_id, script_id, vars: {name: value}}` → `{ok, channel}`
- Expands `{{name}}` → value (validated: no newlines in values unless multi-line allowed flag), execs on the session worker channel; output via `oars.ssh.poll`; exit code from channel.
- Script body executed via the shell: `bash -c '<body with vars>'` — values are **argument-quoted** (single-quote escaping) to prevent injection via variables; scripts are the user's own code, but variables must not break out.
### `oars.scripts.broadcast` `{script_id, server_ids[], vars}` → `{ok, run_id}`
### `oars.scripts.broadcastPoll` `{run_id}` → per-server status/output deltas (streams keyed by server_id, same cursor protocol; a `RunState` record lives in the manager)
### `oars.scripts.broadcastCancel` `{run_id}`

## 6. Zig core design

- `src/scripts.zig` — Script model + store (`<data>/scripts.json`), template expansion (`expandTemplate` with `{{name}}` scan — pure, unit-tested), quoting helper.
- Broadcast runner: `BroadcastRun {id, script, servers[], per_server: {channel, stream, status}}` in a manager map; each server's exec goes through its own session worker (fan-out is *ours*, not the server's); a lightweight coordinator thread just aggregates statuses (or poll-driven from the frontend — v1: poll-driven, no extra thread).

## 7. Data model

- `<data>/scripts.json`: `[{id, name, description, tags[], color, body, created_at, updated_at, run_count, last_run_at}]`.
- Last-used variable values per script (client-side localStorage, not persisted to disk config).

## 8. Security

- Scripts are user-authored; variables are escaped/quoted; broadcast is two-step (dry-run + confirm); destructive-tagged scripts add a second confirm; every broadcast/run writes an audit entry (spec 15) with the expanded command.
- Scripts run as the SSH user — no privilege elevation beyond the session.

## 9. Performance

- Broadcast streams are read per-server with the poll budget; N servers = N channel streams, all worker-side (no new threads per server).
- Dry-run expansion is instant (client-side render of expanded text).

## 10. Edge cases

- Server unreachable during broadcast → marked `skipped (unreachable)`, reported, not silently dropped.
- Duplicate server selection → deduped.
- Variable referenced but not provided → run blocked with "missing variable: X" (no partial substitution).
- Script > 64 KB → rejected at save.
- Broadcast to 20+ servers → streams windowed (show first 8, rest "waiting") to protect the UI.

## 11. Testing

- Unit: template expansion (nested braces, missing vars, quoting/injection attempts), store round-trip.
- Integration: run script on container; broadcast to 2 containers; verify exit codes and cancel behavior.
- Manual: destructive double-confirm, dry-run preview accuracy.

## 12. Acceptance criteria

- [ ] Script CRUD + run with variables works end-to-end.
- [ ] Variable injection attempts are neutralized (tested).
- [ ] Broadcast shows per-server dry-run, confirms, streams side-by-side, reports per-server results.
- [ ] Audit entries written for every run.
