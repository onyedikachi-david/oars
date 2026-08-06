# Spec 15 — Command History & Audit

**Status:** ✅ backend in (UI pending): bounded history/audit journals with
write-time redaction, tracked-exec capture (exit, duration, snippet),
replay with redacted-refusal, type-to-confirm clear · **Depends on:** 02 (exec capture), 06/07/09/10/11/12 (audit hooks) · **Spec owner:** core

## 1. Overview

Two local logs: **history** (committed interactive and app-initiated commands,
searchable and replayable, with best-effort secret redaction) and **audit**
(append-oriented record of every mutating action the app performed — runs,
broadcasts, deploys, key changes, backups, AI approvals). This is the
"logged for audit" promise made by specs 06–12.

## 2. Goals / non-goals

**Goals**
- Capture committed interactive shell commands and app-initiated exec, script,
  deployment, backup, and AI commands with timestamp, exit, and a bounded
  output snippet.
- Redact secrets (values the app knows: env var values, passwords, tokens) from stored text.
- Audit entries for every mutating action: actor ("local user"), action, target, command list, result.
- Search + replay (re-run a history entry as an exec or script).
- Bounded storage (ring: 2,000 entries history, 5,000 audit), exportable (spec 17).

**Non-goals**
- No keystroke-level recording of interactive sessions (only committed command lines), no remote sync, no tamper-proof guarantees (it's a local log, not a SIEM).

## 3. User stories

- "What did I run on prod-api yesterday?" — search history, see the command, re-run it.
- "Did that deploy actually run?" — audit shows the deploy, its steps, and who clicked (me).
- A secret Oars supplied to an operation is masked when I look back. The UI
  warns that an unknown secret typed directly into a remote shell cannot be
  identified with certainty.

## 4. UI/UX

### 4.1 History view (palette `/` + per-server tab)
- Rows: time · server · command (mono, redacted) · exit (✓/code) · duration · output snippet (first 2 lines).
- Filters: server, status, text; `↩` on a replayable row → "Re-run" (opens
  script-save confirm or execs directly with a confirm). A redacted command is
  not replayable unless its secret fields are structured and can be requested
  again without recovering them from stored text.
- Redaction: replaced with `••••`; tooltip "redacted secret".
- The terminal header shows `History: full` when verified shell integration is
  active and `History: app commands only` otherwise. The latter links to the
  approval-gated setup helper for Bash, Zsh, or Fish.

### 4.2 Audit view (app-level, ⌘ palette ">audit")
- Table: time · action type (deploy.run, access.offboard, backup.run, ai.approved, sshkeys.revoke…) · target(s) · command(s) · result.
- Filters by type; export CSV (spec 17); clear requires typing "CLEAR".

### 4.3 Empty state: "Nothing executed yet — commands you run land here automatically."

## 5. Bridge API

### `oars.history.record` (internal) — `{operation_id, server_id, kind: shell|exec|script|ai|deploy|backup|…, command, exit?, duration_ms, output_snippet?}`
- The feature that creates the operation assigns `operation_id`; channel
  completion updates the same record. This avoids timestamp-based dedupe.
- Raw PTY input cannot reconstruct a committed command reliably. For supported
  shells, an optional remote integration script emits nonce-bearing OSC 633
  command-start, exact-command, and command-finished records. Oars strips these
  control records before normal terminal rendering and records only complete,
  nonce-valid commands. Without verified integration, capture remains
  app-initiated only and the UI states that reduced coverage.
### `oars.history.list` `{server_id?, q?, limit}` → `{ok, entries}` (redacted at write time)
### `oars.history.replay` `{entry_id}` → exec confirm → `{ok, channel}`
### `oars.audit.list` `{q?, type?, limit}` → `{ok, entries}` · `oars.audit.export` → via spec 17
### `oars.audit.clear` `{confirm: "CLEAR"}` → `{ok}` (type-to-confirm)

## 6. Zig core design

- `src/history.zig` — `HistoryStore` + `AuditStore` use bounded JSON Lines
  journals (`history.jsonl`, `audit.jsonl`) with atomic compaction. A storage
  worker owns file I/O so bridge handlers do not pause the UI.
  **Landed as:** synchronous O(1) positional appends + fsync, mutex-
  serialized, reusing the `audit.Store` pattern proven through specs 03–14 —
  appends happen on the session worker (already off the UI thread) or in
  short handler sections, and the in-memory index keeps reads off the disk
  entirely (see §13).
- `src/shell_integration.zig` parses OSC 633 `A/B/C/D/E` records and associates
  the exact command from `E` with its completion and exit status from `D`.
  Bash, Zsh, and Fish integration scripts live in versioned app resources. The
  setup helper writes them under `~/.config/oars/` and adds one guarded source
  line to the relevant shell startup file only after preview and approval.
- Each terminal session creates a random nonce and passes it to the integration
  script. Records without that nonce are terminal output, not history metadata.
- The nonce prevents accidental or uninformed output from becoming metadata;
  it is not a trust boundary against a hostile remote account that can inspect
  or modify its own shell integration. The UI labels this as shell-reported
  history.
- Redaction starts with exact secret values and structured secret fields from
  the operation. Pattern matching is defense in depth and must not use broad
  flags such as `-p` that can hide harmless arguments while missing secrets.

## 7. Data model

- `history.jsonl`: `{id, operation_id, ts, server_id, kind, command, exit, duration_ms, output_snippet, redacted}` records, compacted to the newest 2,000.
- `audit.jsonl`: `{id, operation_id, ts, type, target, commands, result, detail}` records, compacted to the newest 5,000; clear requires confirmation.

## 8. Security

- Redaction is applied **at write time** with the secrets known to that
  operation. A second pass masks narrow, named fields such as
  `PASSWORD=…`, `TOKEN=…`, and `--password …`; it does not treat every `-p`
  argument as a password.
- Audit entries never contain secret values (commands are redacted the same way).
- History/audit are plain JSON on disk (documented; export/encrypt via spec 17).
- The History view states that pattern redaction is best effort for secrets the
  app did not supply. Users can disable interactive history per server and
  clear local history.

## 9. Performance

- Appends are O(1) between compactions. Build an in-memory index on load so
  list queries do not parse thousands of lines on every bridge request.

## 10. Edge cases

- Duplicate capture → update by `operation_id`.
- Shell integration absent, stale, or overridden by shell plugins → keep the
  terminal usable, show `app commands only`, and never infer commands from
  prompt text or raw keystrokes.
- Very long commands → capped at 4 KB stored.
- Secret value changes → old entries keep old masks (masked at write; documented).
- Redacted command selected for replay → ask for each structured secret again,
  or disable replay when the field mapping is unavailable. Never run the
  redaction marker as shell text.
- Disk full → writes fail loudly in the status strip, never crash.

## 11. Testing

- Unit: redaction patterns (env values, flag values, URL passwords), ring compaction, dedupe.
- Integration: Bash, Zsh, and Fish fixtures emit single-line and multiline
  commands, exit codes, and spoofed OSC records; history accepts only valid
  nonce records. Perform an offboard → audit row correct; replay works.

## 12. Acceptance criteria

Backend-verifiable items are ticked as of the spec-15 backend landing
(verified against the container suite; the UI/shell-integration items
remain open frontend work).

- [x] Every app-initiated command lands in history with exit + snippet.
      Tracked execs (`ssh.exec`, scripts, broadcast, deploy steps, backup
      runs, monitor cleanDisk/dropCaches, replay) are recorded at channel
      EOF with exit, duration, and a bounded two-line output snippet.
      Internal plumbing (probes, syntax checks, scans) is never recorded.
- [ ] With shell integration active, committed Bash, Zsh, and Fish commands
      land in history with exact command text and exit status; line editing,
      multiline input, and full-screen programs do not create false entries.
      (Frontend + versioned remote integration scripts — OSC 633 protocol
      per §13 — not yet implemented; see the shell_integration note in §6.)
- [ ] Without shell integration, the UI says `app commands only` and never
      claims complete interactive history. (Frontend.)
- [x] Every secret value known to an operation is absent from stored and
      rendered text. The exact-value pass masks the command AND the output
      snippet with the operation's known secrets (scripts carry their
      secret variable values through to capture); the narrow named-field
      pass (`PASSWORD=…`, `TOKEN=…`, `--password …`, URL userinfo — never
      a blanket `-p`) has unit fixtures and is labeled best effort in §8.
      The `ssh.exec` audit row is redacted the same way.
- [x] A redacted command cannot replay without safe structured re-entry of
      its secret fields. The backend refuses replay of any redacted entry
      with an explicit message; structured re-entry is frontend work.
- [x] Every mutating feature (06–12) writes an audit entry. All existing
      audit call sites write the full entry shape (`type`/`target`/…);
      the container suite asserts exec/script rows land in `oars.audit.list`.
- [ ] History search + replay work from the palette. (Palette is frontend;
      the replay backend path is container-verified.)
- [x] Clear requires type-to-confirm. `oars.audit.clear` accepts only the
      literal `CLEAR` confirm string.

## 13. Research & References

- **Interactive command capture** — an SSH PTY carries opaque bytes, so raw
  client input is not a reliable command boundary after line editing,
  multiline input, or full-screen programs. VS Code's official terminal shell
  integration documentation shows the researched alternative: Bash, Zsh, and
  Fish integration scripts emit command metadata; `OSC 633 ; E` carries the
  exact command line, `C` marks execution, `D` carries the exit code, and an
  optional nonce helps reject spoofed records. Oars uses that protocol through
  its own reviewed remote scripts and reports reduced coverage when integration
  is unavailable (`https://code.visualstudio.com/docs/terminal/shell-integration`).
- **Redaction** — mask-at-write with known secret values and structured secret
  fields, plus narrow patterns such as named password/token options:
  standard secret-scrubbing practice; no external standard, but the
  masking pass is unit-tested with fixtures. The known limitation
  (values that change later keep old masks — masked at write) is
  documented in §10 and is the same tradeoff log-scrubbing tools
  accept.
- **Bounded journals** — JSON Lines supports real append semantics; periodic
  atomic compaction keeps the 2,000 history / 5,000 audit bounds. `fsync`
  requests persistence, but Oars does not call this local, clearable file a
  tamper-proof audit system.
- **No keystroke recording** — per §2 non-goals; shell integration records only
  the command that the shell commits, not each key event or abandoned edit.
- **Replay** — re-running a stored command reuses `oars.ssh.exec`
  (spec 02 §5) and records a new history entry (chainable); confirm
  required because the environment may have changed since the entry
  was captured.

Sources: VS Code terminal shell integration protocol, POSIX fsync(2), spec 02
§5, internal design decisions.

### Corrections forced by implementation (2026-08-06)

- **Storage worker → synchronous appends.** §6 proposed a dedicated storage
  worker thread. The landed implementation appends synchronously with the
  established `audit.Store` pattern (O(1) positional write + fsync, spinlock-
  serialized). Rationale: the capture hook runs on the session worker (never
  the UI thread), handler-side appends are single short writes, and the
  in-memory index (§9) means list/read queries never touch the disk — the
  worker thread would add lifecycle complexity with no measured benefit.
- **Shell integration is not part of the backend landing.** The OSC 633
  integration scripts, the nonce handshake, and the `shell_integration.zig`
  parser remain open work (frontend + remote-script resources). Until then
  the UI's coverage label must show `app commands only`; the capture surface
  that IS landed is app-initiated tracked execs.
- **Known-secret masking of output.** The exact-value pass masks the stored
  output snippet as well as the command. The operation carries its known
  secret values (`history_secrets`) through the exec op to the capture hook;
  scripts populate them from their secret variable values. Pattern masking
  never applies to program output (patterns describe command syntax).
- **Audit entry shape.** The journal line and `oars.audit.list` wire format
  use `type`/`target` (spec §7); journals written by earlier builds with
  `action`/`server_id` still load (aliases on read). App-level actions use
  target `-`. The old `oars.audit.read`-shaped minimal read survives as
  `AuditStore.read` for `oars.ai.history` (spec 11 wire shape unchanged:
  its response still carries `action`).
