# Next Spec Implementation Guide

## Target

Spec 06 (Scripts + Safe Broadcast) is **complete in this checkout** —
see `docs/HANDOVER.md` §34 for the session evidence. The next
implementation target is **spec 07 (One-Click Deployment)**; the
`oars.deploy.*` backend and a basic DeployTab already exist, so follow the
same audit-first procedure used here: re-read the spec, audit the current
checkout against it, and correct the contract together with the code.

The guide below remains the record of the spec 06 corrections and is kept
for maintenance reference.

---

## Spec 06 implementation record (2026-08-11)

Treat the feature spec as the product contract. Do not reduce it to the small scripts UI
that exists in the current checkout.

The current core has a script store, template expansion, single-server runs,
broadcast state, polling, cancellation, audit records, and container tests.
The frontend has a basic list, editor, and run action. The remaining work is
not a visual pass alone. It includes bridge corrections that are required for
an exact preview and reliable result reporting.

Read these sources before editing:

- `docs/DESIGN.md`
- `docs/specs/06-scripts.md`
- `docs/specs/02-terminal.md`, especially the absolute-cursor protocol
- `docs/specs/15-history.md`, especially redaction and audit rules
- `src/scripts.zig`, `src/broadcast.zig`, and the script handlers in
  `src/bridge.zig`
- the session poll, tracked-exec, and close-channel paths in `src/sessions.zig`
- the script tests in `src/main.zig`, `src/integration.zig`, and
  `src/integration_history.zig`
- `frontend/src/ScriptsTab.tsx`, `frontend/src/bridge.ts`,
  `frontend/src/types.ts`, `frontend/src/App.tsx`, and
  `frontend/src/index.css`
- `frontend/preview.html`; extend it and keep every existing mode working
- `docs/research/spec-06-current-state.md`, which records the source audit for
  this guide

## Verified Current State

### Core and bridge

The script store is `<data>/scripts.json`. It stores `id`, `name`,
`description`, `tags`, a hex color, `body`, variable definitions,
`created_at`, `updated_at`, `run_count`, and `last_run_at`. Variable definitions
use `{name,label,secret_default}`. Run-time values are separate and must never
be written to this file.

The core enforces these limits: 1,000 scripts, a 64 KiB body, 200 bytes for a
name or variable label, 4 KiB for a description, 32 tags, 64 bytes per tag,
64 variables, and 16 bytes for a color. A non-empty color must start with `#`.
Variable names use `[A-Za-z_][A-Za-z0-9_]*`.

The bridge registers these commands:

- `oars.scripts.list`
- `oars.scripts.save`
- `oars.scripts.delete`
- `oars.scripts.run`
- `oars.scripts.broadcast`
- `oars.scripts.broadcastPoll`
- `oars.scripts.broadcastCancel`

Template expansion is owned by `src/scripts.zig`. It rejects missing values,
multiline values, invalid placeholders, and ambiguous shell contexts. It
single-quotes each accepted value and escapes an embedded single quote by
closing, escaping, and reopening the quoted string. The expansion also builds
a redacted command and an owned list of secret values for history redaction.
Do not create an independent TypeScript expansion engine and call it exact.

Each run performs a remote `bash -n` syntax check. Broadcast work starts when
the frontend polls. It runs at most four servers at one time. The poll request
uses one absolute cursor per server, so separate views do not consume each
other's output. Completed broadcast records are bounded to 32.

### Gaps that this implementation must correct

The existing frontend bridge defines only list, save, delete, and run. It has
no typed broadcast, poll, or cancel methods. Its script shape also calls the
stored `secret_default` field `secret` and omits the variable label and three
timestamps.

`ScriptsTab` does not send `variables` when it saves. Editing a script can
therefore erase all variable definitions. It sets a new script color to
`blue`, although the core accepts only an empty string or a value that starts
with `#`. It also received epoch nanoseconds as JavaScript numbers and lost
precision before it converted them to milliseconds.
The backend trusts the request's run-time `secret` flag and does not enforce a
stored `secret_default`. A client can therefore demote a stored secret and let
its value reach audit or history output. Stored secret policy must be the
minimum policy; a caller can promote a value to secret but cannot demote it.

The run flow uses browser `prompt` and delete uses browser `confirm`. These
controls do not meet the product dialog contract or the design system. The
run poll replaces prior output with the newest delta, drops poll errors,
ignores dropped-byte gaps and exit status, leaves timers and completed
channels open, and has no stable state for an empty-output command.

The broadcast backend is substantial, but it is not complete enough for the
target UI:

- `oars.scripts.broadcast` stores an empty script name, so polls return an
  empty `script_name`.
- A channel that reaches EOF becomes `done` for every exit code. A nonzero
  exit must become `failed` and retain its exact exit code.
- A poll serializes status and exit before it applies an EOF transition. The
  response can therefore lag one poll behind the state it just observed.
- The syntax check uses Bash, but tracked execution submits the expanded body
  directly to the SSH exec shell. The checked interpreter and the execution
  interpreter can differ. Execute through the same Bash invocation that was
  checked, or change both paths to one documented interpreter.
- The current API starts a broadcast as soon as the user confirms the client
  preview. A client-side copy of the Zig lexer cannot guarantee that the
  preview is the command the core will submit. A script edit between preview
  and start also invalidates the preview.
- Server IDs are deduplicated only after audit records are prepared. Duplicate
  input can produce duplicate audit rows. The active and unpolled run registry
  also has no admission limit.
- One broadcast poll can run four remote syntax checks in sequence. Each check
  can wait 30 seconds, so one bridge call can block for about two minutes.
  Syntax preparation must be incremental or worker-driven.

Do not keep the `backend done` claim after these facts are known. Correct the
contract and implementation together.

## Required Product Flow

The Scripts workspace has three stable areas. A searchable library shows
script name, description, tags, run count, and last run. A focused editor
creates or changes one script and its detected variables. A run workspace
shows inputs, approval, live output, status, and exit results. On narrow
screens, show these areas in sequence instead of squeezing them into columns.

A single-server run uses the current server. A broadcast uses the full server
list from `App`, grouped by the saved server group. The user selects servers,
enters variable values once, reviews the exact prepared command and every
target, confirms, and then sees one result row or panel per server. A script
with an exact, case-insensitive `destructive` tag requires a second focused
confirmation. Color alone must never mark a script as destructive.

The workspace must also know whether its current server is connected. Do not
mount a runnable Scripts page against the first saved server as a hidden
fallback. If no server context is active, ask the user to select one. Add saved
scripts to the command palette so its spec 06 entry point can select a script
and a target instead of only navigating to the Scripts page.

The preview does not contact a remote shell and is not a dry run. Say this in
the dialog. The remote `bash -n` check happens after confirmation and before
execution on each server.

## Corrected Bridge Contract

Keep the existing CRUD and run commands. Add strict shared TypeScript types for
all request and response shapes. Remove script-specific `any` values.

Add a core-owned prepare step for broadcast. One acceptable contract is:

```text
oars.scripts.broadcastPrepare
  {script_id, server_ids[], vars}
  -> {ok, preview_id, script_id, script_name, command,
      redacted_command, servers[], destructive, expires_at}

oars.scripts.broadcast
  {preview_id}
  -> {ok, run_id}

oars.scripts.broadcastPrepareCancel
  {preview_id}
  -> {ok}
```

The core must create the displayed command with the same expansion and Bash
wrapper that execution uses. The prepared record must own the exact expanded
command, redacted command, secret values, deduplicated server IDs, script name,
and destructive state. Commit must execute that record, not reload and expand
the script again. This makes the preview and submitted command identical even
if another view edits the script after preparation.

Prepared records are memory-only, bounded, and short-lived. Expire them after
10 minutes, remove them after commit or explicit cancel, and clear them during
shutdown. Preparation must not increment run counts or write an execution
audit entry. Do not put a secret value in a preview ID, URL, local storage,
preview fixture log, error, or persisted record.

Set explicit admission limits: at most 64 deduplicated servers in one
broadcast, 8 active broadcasts, and 32 uncommitted prepared records. Reject a
new request with a clear error when a limit is reached. These are product
limits for v1. Update them only with a measured memory and worker-capacity
change.

Update spec 06 when this bridge correction is implemented. Do not add a
client-side quote helper as a substitute. If the command names above change
during implementation, keep the two-phase property and document the final
wire shapes in one place.

The existing poll response remains:

```text
{ok, run_id, script_name, canceled, done,
 servers:[{server_id,status,exit,error,cursor?,gap?,eof?,data?}]}
```

Status is `queued | checking | running | done | failed | canceled | skipped`.
Use `checking` while the server worker runs `bash -n`. It occupies one of the
four concurrency slots, but it must not block the bridge poll. Use `done` only
for exit 0. Use `failed` for a nonzero exit, a syntax-check failure, or a
session failure. Use `skipped` when a selected server cannot start. Keep the
actual exit code and backend error. Serialize the result after applying the
current poll transition so `done:true` and every server result agree in the
same response. Update spec 06 with the `checking` state.

For a single run, execute the same prepared Bash command after `bash -n`. Poll
its channel through `oars.ssh.poll` with the view's absolute cursor. Append
each delta, surface `dropped`, record `exit`, and call
`oars.ssh.closeChannel` after EOF or when the user closes the run pane.

## Implementation Order

1. **Lock the wire model.** Add `Script`, `ScriptVariable`, `ScriptDraft`,
   `ScriptRunVars`, `BroadcastStatus`, `BroadcastServerResult`,
   `BroadcastPollResult`, and prepared-preview types to
   `frontend/src/types.ts`. Use `secret_default`, not `secret`, for stored
   definitions. Keep run-time `{value,secret}` separate. Include
   `recovery_error` on list. Add typed wrappers for the complete final bridge
   contract.

2. **Correct core execution and result state.** Make syntax checking and
   execution use the same Bash command. Preserve the script name in broadcast
   state. Mark nonzero exits failed. Apply status transitions before response
   serialization. Enforce each stored `secret_default` even if a caller sends
   `secret:false`. Deduplicate before audit. Add the bounded prepared-preview
   and active-run admission rules. Move syntax checking out of the blocking
   poll path. Keep the four-server concurrency limit and absolute-cursor
   behavior.

3. **Add focused core tests before UI work.** Test preview-to-commit identity,
   edit-after-preview, expiry, cancel, deduped servers, destructive-tag
   matching, secret redaction, Bash wrapper quoting, exit 0, nonzero exit,
   syntax failure, unreachable server, output gap, cancel before start, and
   cancel during execution. Prove that preparing does not audit or increment
   run counts.

4. **Build pure frontend state helpers.** Keep script filtering, variable
   draft reconciliation, millisecond timestamp display, cursor merging, output
   append and cap logic, broadcast summary counts, and stale-response guards
   outside the component. Add Vitest coverage. Define one timestamp wire unit:
   return display timestamps as integer milliseconds, or return nanoseconds as
   decimal strings. Never round-trip epoch nanoseconds through a JavaScript
   `number` as an identity token.

5. **Replace the script library surface.** Use one quiet operational surface,
   not nested cards. Put search and tag filters above a compact script list.
   Show the selected script in a clear detail pane with restrained metadata
   and primary actions for `Run` and `Run on multiple servers`. Keep edit and
   delete secondary. Show recovery errors from a quarantined script store.

6. **Implement the editor without data loss.** Use the shared modal pattern.
   Include name, description, six valid hex swatches, tags, command body, and
   a detected-variable table with name, label, and `Secret value` default.
   Reconcile detected placeholders with saved definitions so an edit
   preserves labels and secret defaults. Show unused definitions and invalid
   placeholder contexts before save. Send the complete script draft on every
   save. Do not trim the command body because leading or trailing whitespace
   can be meaningful shell input.

7. **Implement safe delete.** Replace browser `confirm` with a focused modal
   that names the script and explains that the saved definition will be
   removed. Keep run history under spec 15 rules. Disable repeat submission,
   show the exact backend error, and restore focus when the dialog closes.

8. **Implement the single-run workflow.** Open a variable dialog for every
   stored definition. Mask values whose definition has `secret_default`, but
   do not let the user demote those values. Let the user promote any other
   value to secret for that run. Cache last-used values only in component
   memory for this app session. Never persist them. Show a stable output pane
   even when the command writes no output. Include script, server, running
   state, dropped-output warning, exit code, copy, close, and retry. Stop
   timers and close active channels on server change or unmount.

9. **Implement selection and preparation.** Pass the full `Server[]` into the
   scripts workspace. Group targets, support group selection, show offline or
   unavailable state without hiding the server, dedupe IDs, and require at
   least one target. Collect variables before preparation. Render the exact
   core-prepared command, redacted by default when secrets exist, plus the
   complete target list. Cancel the prepared record when the user backs out.

10. **Implement confirmation and broadcast.** The first confirmation states
    the server count and action. The destructive confirmation is a separate
    step and names the reason. On commit, poll at the documented cadence with
    the view's cursor map. Append deltas per server, report gaps, keep output
    bounded, and render queued, running, succeeded, failed, skipped, and
    canceled states with text and icons. For more than eight servers,
    virtualize or window result bodies while keeping the summary and all
    statuses visible.

11. **Make cancellation honest.** Cancel stops queued starts and closes active
    channels. Label active results `Cancel requested` or `Canceled` as the
    backend reports. Never say that the remote process was killed because SSH
    channel close does not prove process termination. Keep completed server
    results unchanged.

12. **Extend the preview fixture.** Add deterministic script-library empty,
    populated, recovery-error, editor-validation, single-run success,
    no-output, nonzero exit, output-gap, prepare, destructive confirmation,
    2-server success, 20-server mixed results, unreachable, cancel, expiry,
    and stale-response modes. Record request shapes after replacing variable
    values with `***`. Do not place real or fixture secret values in the call
    inspector.

## Design and Accessibility Rules

Use the Oars mineral-paper and paper-night tokens. The script command and live
output use Geist Mono. Labels, help, status, and controls use Geist Sans. Use
Lucide icons only. Do not use accent stripes, emoji, browser prompts, browser
confirms, unexplained status colors, or a grid of large decorative cards.

Keep one primary action per step. Dialogs need a title, one short explanation,
the affected script or server set, a clear primary action, and cancel. Trap
focus, close on Escape when safe, restore focus, label every input, associate
errors with their fields, and announce run-status changes without moving
keyboard focus. A destructive second confirmation must remain usable without
color perception.

Show the previous library during refresh. Use a clear first-load state, an
empty state with the spec example, inline errors that preserve user input, and
an explicit retry. Motion is optional and must stay within the 150–220 ms
design range. Polling must not cause layout shifts.

## Security and Data Rules

- The script body is trusted user-authored code. Variable values are untrusted
  data. Quoting limits what a value can do; it does not make the script safe.
- The core owns placeholder validation, expansion, preview, redaction, and the
  final execution wrapper.
- Secret values can exist in transient frontend state and the prepared/run
  memory records only. Clear those values when a dialog, preview, or run ends.
- Never persist run-time values in `scripts.json`, local storage, history,
  audit detail, preview recordings, analytics, or error text.
- Write one audit record per attempted server execution with the script ID,
  script name, variable names, and redacted command. Do not write an execution
  audit record for an uncommitted preview.
- Keep bridge origins restricted to the packaged app and approved development
  origins. Do not add a broad origin to make preview testing easier.

## Validation Gate

Do not mark spec 06 complete until all of these pass:

- `zig build`
- `zig build test`
- `npm --prefix frontend test`
- `npm --prefix frontend run build`
- `git diff --check`
- Core tests for every corrected bridge and state transition listed above
- Frontend tests for editor preservation, secret defaults, filtering,
  timestamp formatting, stale requests, cursor merging, delta append, output
  caps, result summaries, and timer cleanup
- Container integration for one successful run, no-output run, nonzero exit,
  bad Bash syntax, missing Bash, injection value, two-server broadcast,
  unreachable server, mixed exits, secret redaction, and cancellation
- Preview-to-commit equality checked at the final tracked-exec boundary
- Desktop review at 1440 x 1000 in light and dark themes
- Mobile review at 390 x 844 with no page overflow, hidden confirmation, or
  inaccessible output
- Keyboard-only review for library, editor, variable entry, target selection,
  confirmation, results, cancel, retry, and delete
- No browser prompt or confirm, script-specific `any`, swallowed poll error,
  leaked timer, orphaned channel, stale server result, secret recording,
  console error, text overlap, or polling layout shift

After validation, update `docs/specs/06-scripts.md`, `docs/specs/README.md`,
`docs/ROADMAP.md`, and `docs/HANDOVER.md` with evidence from the current
checkout. Mark only the checks that ran. Do not call the feature complete from
a build or typecheck alone.
