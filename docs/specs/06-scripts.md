# Spec 06 — Scripts + Safe Broadcast

**Status:** ✅ backend in (frontend UI pending) · **Depends on:** 02 (exec), 01 · **Spec owner:** core + frontend

## 1. Overview

A personal library of shell commands with `{{variable}}` templating, run
with one click on the server you're looking at. **Oars+ differentiator:**
safe broadcast — run one script across a *selection* of servers with a
per-server expansion preview and a single confirmed execution, side-by-side
streams. This is an Oars design choice; current public CtrlOps docs do not
provide enough evidence for the earlier claim that it explicitly refuses
fan-out.

## 2. Goals / non-goals

**Goals**
- CRUD scripts: name, description, tags, color, body with `{{var}}` placeholders.
- Run on current server; run-time variable prompts; live output in a pane.
- Run counts + last-run stamps per script; search + tag filter.
- Safe broadcast: select servers → expansion preview → confirm → bounded
  parallel streams with per-server exit codes. The preview does not execute the
  command and must not be called a dry run.
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
- Editor (modal or right pane): name, description, tags, color picker (6
  swatches), command textarea with `{{` autocomplete, and a detected-variable
  table. Each variable has a label and `Secret value` default. The flag
  controls masked input, storage, history, and audit; name matching can only
  suggest it.
- Run flow: Run → variable prompt dialog (per var, prefilled from this app
  session only) → output pane streams (header: script name · server · exit
  code). Values are not persisted between launches in v1.

### 4.2 Safe broadcast flow
1. From a script: **Run on multiple servers…** → selection sheet (server list with checkboxes + groups).
2. Expansion preview: for each server, show the exact command text that Oars
   will submit. This is not proof that the remote shell will accept it.
3. Confirm ("Run on N servers") — scripts tagged destructive require an extra confirm ("These are marked destructive").
4. Execution: streams side-by-side (each server a column/row with its own output + status); per-server exit codes; summary line "6/6 succeeded" / "db-02 failed (exit 2)".
5. Cancel stops remaining queued servers (running ones finish or are killed via channel close).

### 4.3 States
- No scripts → empty state with "Save your first script" + example button (prefills `sudo tail -f /var/log/{{service}}/error.log`).
- Run failed → toast "Script failed, check terminal output" + real error visible in the pane (never rewritten).

## 5. Bridge API

### `oars.scripts.list` → `{ok, scripts}` · `oars.scripts.save` `{script}` → `{ok, script}` · `oars.scripts.delete` `{id}` → `{ok}`
- Save is an upsert by id (the core generates ids for creates); edits
  preserve `created_at`, `run_count`, and `last_run_at`. Body > 64 KB,
  duplicate/invalid variables, and bad tags/colors are rejected.
### `oars.scripts.run` `{server_id, script_id, vars: {name: {value, secret}}}` → `{ok, channel}`
- Each placeholder must occupy a shell word by itself. Placeholders inside
  quotes, redirections, command names, assignments, or shell syntax are
  rejected. Oars replaces each valid placeholder with a single-quoted shell
  literal and tests the resulting command with `bash -n` before execution.
  Multiline values are not supported in v1. Scripts are user-authored code;
  this rule only prevents a variable value from adding shell syntax.
- Mid-word placeholders ARE valid (`tail -f /var/log/{{service}}/error.log`
  is the spec's own example): the quoted value merges into the word safely.
  Rejected contexts: inside quotes/backticks/`$(…)`/`${…}`/comments, at
  command-name position, adjacent to `=`, or touching `$`, quotes, braces,
  or backslash. A placeholder that follows a redirection operator is a
  redirection target and is rejected.
- `bash -n` runs on the server (exit 127 = bash unavailable); a missing
  variable blocks the run with `missing variable: X` (no partial
  substitution). The command is never executed when the check fails.
- Runs bump `run_count`/`last_run_at` and write an audit entry
  (`scripts.run`) with the variable names and the redacted command —
  secret values are masked as `***` and never written.
### `oars.scripts.broadcast` `{script_id, server_ids[], vars}` → `{ok, run_id}`
- Duplicate server ids are deduped; the expansion happens once; every
  server is audited (`scripts.broadcast`, one entry per server). At most
  four servers run at a time; polling starts queued work as slots free.
### `oars.scripts.broadcastPoll` `{run_id, cursors: {server_id: cursor}}` → per-server status/output deltas
- Streams are keyed by server id and channel. Each caller returns its own
  absolute cursor map under the spec 02 protocol; polling one broadcast view
  cannot drain another view. Response: `{ok, run_id, script_name, canceled,
  done, servers:[{server_id, status, exit, error, cursor, gap, eof, data}]}`
  with status ∈ queued | running | done | failed | canceled | skipped
  (skipped = unreachable at start, reported not dropped). Terminal runs
  stay readable for a bounded history.
### `oars.scripts.broadcastCancel` `{run_id}`
- Queued servers never start; running channels are closed and reported
  `canceled` with "cancel requested" — closing a channel does not prove
  the remote process died.

## 6. Zig core design

- `src/scripts.zig` — Script model + store (`<data>/scripts.json`), template expansion (`expandTemplate` with `{{name}}` scan — pure, unit-tested), quoting helper.
- Broadcast runner: `BroadcastRun {id, script, servers[], per_server:
  {channel, stream, status}}` in a manager map. Run at most four servers at a
  time by default. Polling starts queued work as slots become free.

## 7. Data model

- `<data>/scripts.json`: `[{id, name, description, tags[], color, body,
  variables:[{name,label,secret_default}], created_at, updated_at, run_count,
  last_run_at}]`. It stores variable definitions, never run-time values.
- Last-used variable values live only in frontend memory for the current app
  session. Oars does not put arbitrary command values in localStorage.

## 8. Security

- Scripts are user-authored; variables follow the word-only rule; broadcast is
  preview + confirm; destructive-tagged scripts add a second confirm. Audit
  stores a redacted command and structured variable names. Values marked
  secret are never written to history.
- Scripts run as the SSH user — no privilege elevation beyond the session.

## 9. Performance

- Broadcast streams are read per-server with the poll budget; N servers = N channel streams, all worker-side (no new threads per server).
- Expansion preview is client-side and should complete within one frame for a
  normal script library.

## 10. Edge cases

- Server unreachable during broadcast → marked `skipped (unreachable)`, reported, not silently dropped.
- Cancel stops queued starts and closes active channels. The result is
  `cancel requested` until Oars can verify remote process termination; channel
  close alone is not a kill guarantee.
- Duplicate server selection → deduped.
- Variable referenced but not provided → run blocked with "missing variable: X" (no partial substitution).
- Script > 64 KB → rejected at save.
- Broadcast to 20+ servers → streams windowed (show first 8, rest "waiting") to protect the UI.

## 11. Testing

- Unit: template lexer boundaries, nested braces, missing variables,
  quoting/injection attempts, secret metadata, and store round-trip.
- Integration: run script on container; broadcast to 2 containers; verify exit codes and cancel behavior.
- Manual: destructive double-confirm, expansion-preview accuracy.

## 12. Acceptance criteria

- [x] Script CRUD + run with variables works end-to-end.
- [x] Variable injection attempts are neutralized (tested against the
      live container: a value containing `'; touch …` stays a literal
      argument).
- [ ] Broadcast shows a per-server expansion preview, confirms, streams
      side-by-side, and reports per-server results (backend done; the
      preview/confirm UI is frontend).
- [x] Audit entries written for every run (redacted command, variable
      names; secret values never written — verified).

## 13. Research & References

- **Single-quote quoting** — verified in the GNU Bash manual §3.1.2.2
  (`https://www.gnu.org/software/bash/manual/html_node/Single-Quotes.html`):
  "Enclosing characters in single quotes preserves the literal value of
  each character within the quotes. A single quote may not occur
  between single quotes, even when preceded by a backslash." Hence the
  standard escape for a literal quote is `'\''` (close, escape, reopen)
  — the spec's "argument-quoted (single-quote escaping)" claim maps to
  this rule. This is the same quoting the POSIX shell command language
  specifies for single-quoted strings
  (`https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_02`).
  **Correction:** quoting a value is not enough when a placeholder can appear
  inside existing shell syntax. The contract now limits placeholders to whole
  shell words and rejects ambiguous contexts before expansion.
- **`bash -c '<script>'`** — executing a script via `bash -c` is the
  documented Bash invocation mode (`bash -c string` processes the
  string as commands; Bash manual §6.1 "Bash Invocation"). The command
  string is the user's own script (trusted author); only the
  `{{variable}}` values are untrusted and must be single-quote-escaped
  as above. This is the same escaping discipline x11vnc-style wrappers
  and the rclone docs recommend for shell arguments
  ("Use single quotes `'` by default…" — rclone docs,
  `https://rclone.org/docs/#quoting-and-the-shell`).
- **Broadcast fan-out** — each server's exec runs through its own
  session worker (spec 02 §6); no server-side fan-out tools are used
  (CtrlOps-style broadcast tools are server-side daemons — ours is
  client-orchestrated by design, stated in §1).
- **Destructive-tag double-confirm** — product guardrail; no external
  reference needed.
- **Audit** — every run appends to the audit store (spec 15 §5); the
  bridge-side record hooks are specified there.

Sources: GNU Bash manual (quoting, invocation), POSIX shell command
language (opengroup), rclone docs (quoting section).

### Corrections / verified in the implementation

- **The word rule is an adjacency rule, not an isolation rule.** The
  spec's own example body is `tail -f /var/log/{{service}}/error.log`,
  where the placeholder sits inside a path word — so placeholders may
  border ordinary word characters, and the single-quoted value merges
  into the word (quotes are removed last by the shell; the value can
  never add syntax). Rejected contexts: quoting, command substitutions,
  parameter expansions, comments, command-name position, assignments
  (`=` on either side), redirection targets, and adjacency to `$`, quotes,
  backslash, or braces.
- **`bash` is not preinstalled on the alpine dev container** — added to
  `scripts/dev-sshd/Dockerfile` (the `bash -n` check needs it).
- **`std.json.ObjectMap` fields break the Zig 0.16 static parser**
  (`defaultValue()` comptime error) — the vars/cursors maps parse as
  `std.json.Value` and are read via `.object`.
- **Broadcasts bump `run_count`/`last_run_at` too** (a broadcast is a
  run).
- **Status transitions must fire once**: a done server keeps being polled
  (late cursors still drain retained data), so the `running → done`
  transition is guarded.
- **The poll response serializes `data` before freeing the polls** —
  `ChannelPoll.deinit` owns the data buffer; writing after the frees
  emitted DebugAllocator's 0xAA fill (caught by the container test's
  UTF-8 check).
