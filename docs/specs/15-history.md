# Spec 15 — Command History & Audit

**Status:** 📋 · **Depends on:** 02 (exec capture), 06/07/09/10/11/12 (audit hooks) · **Spec owner:** core

## 1. Overview

Two logs with one store: **history** (every command executed in a
session, searchable and replayable, secrets redacted) and **audit**
(append-only record of every mutating action the app performed — runs,
broadcasts, deploys, key changes, backups, AI approvals). This is the
"logged for audit" promise made by specs 06–12.

## 2. Goals / non-goals

**Goals**
- Capture executed commands per server (shell input lines + exec commands) with timestamp, exit, and truncated output.
- Redact secrets (values the app knows: env var values, passwords, tokens) from stored text.
- Audit entries for every mutating action: actor ("local user"), action, target, command list, result.
- Search + replay (re-run a history entry as an exec or script).
- Bounded storage (ring: 2,000 entries history, 5,000 audit), exportable (spec 17).

**Non-goals**
- No keystroke-level recording of interactive sessions (only committed command lines), no remote sync, no tamper-proof guarantees (it's a local log, not a SIEM).

## 3. User stories

- "What did I run on prod-api yesterday?" — search history, see the command, re-run it.
- "Did that deploy actually run?" — audit shows the deploy, its steps, and who clicked (me).
- A password I typed into a command is masked when I look back.

## 4. UI/UX

### 4.1 History view (palette `/` + per-server tab)
- Rows: time · server · command (mono, redacted) · exit (✓/code) · duration · output snippet (first 2 lines).
- Filters: server, status, text; `↩` on a row → "Re-run" (opens script-save confirm or execs directly with a confirm).
- Redaction: replaced with `••••`; tooltip "redacted secret".

### 4.2 Audit view (app-level, ⌘ palette ">audit")
- Table: time · action type (deploy.run, access.offboard, backup.run, ai.approved, sshkeys.revoke…) · target(s) · command(s) · result.
- Filters by type; export CSV (spec 17); clear requires typing "CLEAR".

### 4.3 Empty state: "Nothing executed yet — commands you run land here automatically."

## 5. Bridge API

### `oars.history.record` (internal) — `{server_id, kind: shell|exec|script|ai|deploy|…, command, exit?, duration_ms, output_snippet?}` — called by the worker when a command channel completes AND by features after their actions; dedupe by (server, ts, command).
- Shell line capture: the worker can't see shell input (it's channel bytes) — **capture strategy:** the frontend records lines it sends that end with `\n` (from `oars.ssh.input`) when a shell prompt is detected; simplest reliable v1: record **exec/script/deploy/AI commands only** (all known to the app), skip raw shell line parsing (note in docs; interactive history = client-side xterm scrollback). **Decision: v1 records app-initiated commands only.**
### `oars.history.list` `{server_id?, q?, limit}` → `{ok, entries}` (redacted at write time)
### `oars.history.replay` `{entry_id}` → exec confirm → `{ok, channel}`
### `oars.audit.list` `{q?, type?, limit}` → `{ok, entries}` · `oars.audit.export` → via spec 17
### `oars.audit.clear` `{confirm: "CLEAR"}` → `{ok}` (type-to-confirm)

## 6. Zig core design

- `src/history.zig` — `HistoryStore` + `AuditStore` (two ring-bounded JSON files: `<data>/history.json`, `<data>/audit.json`; append with periodic compaction), redaction module (`redact(text, secrets[])` — replaces known secret values and `PASSWORD=…`-style patterns via regex-lite matching; unit-tested), capture hooks (exec channel completion, feature action wrappers).
- All writes happen on the main thread (bridge handlers); file writes are async-safe (small appends, fsync on audit).

## 7. Data model

- history.json: `[{id, ts, server_id, kind, command, exit, duration_ms, output_snippet, redacted:bool}]` (ring 2,000).
- audit.json: `[{id, ts, type, target, commands[], result: ok|failed|error, detail}]` (ring 5,000, append-only, clear requires confirm).

## 8. Security

- Redaction is applied **at write time** with the secrets known to that operation; a second pass masks patterns (`(PASSWORD|TOKEN|SECRET|KEY)=…`, `--password …`, `-p …`).
- Audit entries never contain secret values (commands are redacted the same way).
- History/audit are plain JSON on disk (documented; export/encrypt via spec 17).

## 9. Performance

- Writes are O(1) appends; list queries are linear scans over ≤ 5,000 entries with a 50 ms budget (fine).

## 10. Edge cases

- Duplicate capture (frontend + worker both record) → dedupe by (ts, server, command).
- Very long commands → capped at 4 KB stored.
- Secret value changes → old entries keep old masks (masked at write; documented).
- Disk full → writes fail loudly in the status strip, never crash.

## 11. Testing

- Unit: redaction patterns (env values, flag values, URL passwords), ring compaction, dedupe.
- Integration: run commands on the container → history rows correct; perform an offboard → audit row correct; replay works.

## 12. Acceptance criteria

- [ ] Every app-initiated command lands in history with exit + snippet.
- [ ] Secrets are masked in stored and rendered text (tested with fixtures).
- [ ] Every mutating feature (06–12) writes an audit entry.
- [ ] History search + replay work from the palette.
- [ ] Clear requires type-to-confirm.
