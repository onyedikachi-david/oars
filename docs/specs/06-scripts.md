# Spec 06 — Scripts + Safe Broadcast

**Status:** ✅ v1 frontend + backend implemented (2026-08-11) · **Depends on:** 02 (exec), 01 · **Spec owner:** core + frontend

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

### `oars.scripts.list` → `{ok, scripts}` · `oars.scripts.validate` `{body}` → `{ok}` · `oars.scripts.save` `{script}` → `{ok, script}` · `oars.scripts.delete` `{id}` → `{ok}`
- Save is an upsert by id (the core generates ids for creates); edits
  preserve `created_at`, `run_count`, and `last_run_at`. Body > 64 KB,
  duplicate/invalid variables, and bad tags/colors are rejected. The
  stored `secret_default` is the **minimum secret policy**: a caller may
  promote a run-time value to secret but can never demote a stored one.
- The wire carries `secret_default` (not `secret`) on stored definitions.
- The core sends real-time script timestamps and preview expiry as integer
  epoch milliseconds. Epoch nanoseconds never cross JSON as a JavaScript
  number. `validate` scans the complete body with the core lexer, so an
  earlier valid placeholder cannot hide a later invalid context.
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
- **The checked interpreter executes the command**: the run submits the
  exact exec string `bash -c '<expanded command>'` (single-quoted via the
  shared shell-quote helper) — the same `-c` argument the `bash -n -c`
  check validated — so a non-Bash account shell can never interpret the
  script differently from the check.
- Runs bump `run_count`/`last_run_at` and write an audit entry
  (`scripts.run`) with the variable names and the redacted command —
  secret values are masked as `***` and never written.
### Two-phase safe broadcast (spec 06 §4.2/§5): `oars.scripts.broadcastPrepare` → `oars.scripts.broadcast` → `oars.scripts.broadcastPrepareCancel`
- `oars.scripts.broadcastPrepare` `{script_id, server_ids[], vars}` →
  `{ok, preview_id, script_id, script_name, command, redacted_command,
  servers:[{server_id}], destructive, expires_at}`. The core expands the
  template once, enforces stored secret policy, dedupes server ids
  (≤ 64), and **freezes the exact exec + check strings** in a memory-only
  preview record. Writes NO audit row and bumps NO run count. Expires
  after 10 minutes; at most 32 prepared records exist at once. Secret
  values never appear in the preview id.
- `oars.scripts.broadcast` `{preview_id}` → `{ok, run_id}` executes the
  frozen record **verbatim** — a script edit between preview and confirm
  can never change what runs. Audits one row per unique server
  (`scripts.broadcast`), bumps the run count, admits at most 8 active
  broadcasts, and removes the preview.
- `oars.scripts.broadcastPrepareCancel` `{preview_id}` → `{ok}` drops an
  uncommitted preview.
- Duplicate server ids are deduped once, before preview or audit, so
  duplicate selections can never produce duplicate audit rows.
### `oars.scripts.broadcastPoll` `{run_id, cursors: {server_id: cursor}}` → per-server status/output deltas
- Streams are keyed by server id and channel. Each caller returns its own
  absolute cursor map under the spec 02 protocol; polling one broadcast view
  cannot drain another view. Response: `{ok, run_id, script_name, canceled,
  done, servers:[{server_id, status, exit, error, cursor, gap, eof, data}]}`
  with status ∈ queued | **checking** | running | done | failed | canceled |
  skipped. `checking` = the server worker is running `bash -n`; it occupies
  one of the four concurrency slots but never blocks the bridge poll (the
  check runs on the session worker as an internal channel — syntax
  preparation is worker-driven, so one bridge call can never wait through
  several 30 s checks). `done` only for exit 0; `failed` for a nonzero
  exit (exact code retained), a syntax-check failure, or a session
  failure; `skipped` = unreachable at start (reported, not dropped).
  Transitions are applied before the response serializes each server, so
  `done:true` and every server result agree in the same response. Terminal
  runs stay readable for a bounded history.
### `oars.scripts.broadcastCancel` `{run_id}`
- Queued servers never start; running channels are closed and reported
  `canceled` with "cancel requested" — closing a channel does not prove
  the remote process died. In-flight syntax checks are abandoned; their
  worker completion frees the outcome. Before close, the core captures a
  bounded terminal output window with its absolute range so independent
  consumers can still read canceled output and receive an honest gap.

## 6. Zig core design

- `src/scripts.zig` — Script model + store (`<data>/scripts.json`), template expansion (`expandTemplate` with `{{name}}` scan — pure, unit-tested), quoting helper, and the `bash -c`/`bash -n -c` exec/check string builders (checked interpreter = executing interpreter).
- Broadcast runner: `BroadcastRun {id, script, servers[], per_server:
  {channel, stream, status}}` in a manager map. Run at most four servers at
  a time by default (syntax checks occupy the same slots). Polling starts
  queued work as slots become free.
- **Worker-driven syntax checks** (spec 06 §5): each `bash -n -c` runs as an
  internal exec channel on the target's session worker (`syntax_check` op +
  heap `ScriptCheckOutcome` following the session-30 abandon() protocol).
  The bridge poll enqueues the check and reads the outcome on later polls —
  a slow or absent server can never block a bridge call, and `checking`
  status is honest.
- **Two-phase broadcast** (spec 06 §5): `broadcast.Previews` — a bounded
  (32), memory-only registry of prepared records holding the frozen exec
  string, check string, redacted copy, secret values, variable names,
  deduped targets, and destructive state. Records expire after 10 minutes,
  are removed on commit/cancel, and are cleared on manager shutdown. Commit
  (`oars.scripts.broadcast`) replays the record verbatim: audit one row per
  unique server, then `Runs.start`.
- Admission limits (v1): 64 deduplicated servers per broadcast, 8 active
  broadcasts, 32 prepared previews.

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
- [x] Broadcast shows a per-server expansion preview, confirms, streams
      side-by-side, and reports per-server results — two-phase
      prepare/commit, worker-driven `checking`, `done` only for exit 0,
      mixed done/failed/skipped results, preview-to-commit identity
      (edit-after-preview runs the prepared command), and cancel
      (verified against the live container; UI reviewed in the preview
      harness).
- [x] Audit entries written for every run (redacted command, variable
      names; secret values never written — verified). Stored
      `secret_default` is the minimum policy: a demoted value is still
      masked (verified against the live container).
- [x] No browser prompt/confirm; all dialogs follow the product modal
      pattern; secrets never recorded in the preview call inspector.

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
- **2026-08-11 (spec 06 completion): the broadcast contract is
  two-phase.** `oars.scripts.broadcast` no longer accepts
  `{script_id, server_ids, vars}`; callers prepare first
  (`broadcastPrepare`), review the frozen command, then commit by
  `preview_id`. Rationale: a client-side copy of the Zig lexer can never
  guarantee that a preview equals what the core submits, and a script
  edit between preview and start previously invalidated the preview.
  The frozen record makes preview-to-commit identity structural.
- **2026-08-11: `checking` is a first-class broadcast status.** Syntax
  checks moved from the blocking poll path (up to 4 × 30 s per bridge
  call) to the session worker via an internal channel + heap outcome
  (the session-30 abandon() protocol). A check occupies one of the four
  concurrency slots; `done` is emitted only for exit 0 and nonzero exits
  are `failed` with the exact code; transitions serialize after they are
  applied.
- **2026-08-11: the checked interpreter is the executing interpreter.**
  The old bridge validated `bash -n -c <quoted>` but exec'd the unwrapped
  command through the account shell. Runs now submit
  `bash -c '<expanded>'` — the same single-quoted `-c` argument the check
  validated (spec 06 §13's `bash -c` reference now applies to execution
  as well as checking).
- **2026-08-11: stored `secret_default` is the minimum policy.** A caller
  may promote a run-time value to secret but cannot demote a stored
  secret; a demoted value could otherwise reach audit/history unmasked.
- **2026-08-11: admission limits.** 64 deduplicated servers per
  broadcast, 8 active broadcasts, 32 prepared previews, 10-minute preview
  TTL — all enforced with explicit errors. Duplicate server ids are
  deduped before preview/audit so duplicate selections cannot produce
  duplicate audit rows; audit rows are written at commit, never at
  prepare.
