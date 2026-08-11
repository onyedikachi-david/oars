# Spec 06 current-state audit

**Date:** 2026-08-11  
**Scope:** First-party sources in this checkout only. This note describes the
current implementation. The product contract remains
[`docs/specs/06-scripts.md`](../specs/06-scripts.md).

## Verdict

The native script store, template expansion, single-server run, broadcast
state machine, audit path, and container coverage exist. The frontend is not a
complete implementation of Spec 06. It has a basic script list/editor and a
single-server run button, but its wire types do not match Zig, its default
color cannot pass backend validation, it has no safe-broadcast flow, and the
preview has no script fixtures. Two backend behaviors also contradict the
contract: a nonzero broadcast exit is labeled `done`, and broadcast poll
returns an empty `script_name`. The backend also checks Bash syntax but submits
the raw command, so the interpreter that checks a script is not pinned as the
interpreter that executes it.

## Verified native implementation

- `Script` persists `id`, name, description, tags, color, body, variable
  definitions, creation/update times, run count, and last-run time. A variable
  definition is `{name,label,secret_default}`. Limits include a 64 KiB body,
  1,000 scripts, 64 variables, 32 tags, and 200-byte names
  ([`src/scripts.zig:18-52`](../../src/scripts.zig#L18-L52),
  [`src/scripts.zig:155-176`](../../src/scripts.zig#L155-L176)).
- The store is mutex-protected. It rewrites `scripts.json`, applies mode 0600,
  preserves run metadata on edit, and moves malformed JSON to a timestamped
  quarantine path instead of silently overwriting it
  ([`src/scripts.zig:181-258`](../../src/scripts.zig#L181-L258),
  [`src/scripts.zig:260-370`](../../src/scripts.zig#L260-L370)).
- Template expansion rejects missing or multiline values and ambiguous shell
  contexts. It replaces accepted values with one single-quoted shell word. It
  also builds a separate redacted command and deduplicated variable-name list
  ([`src/scripts.zig:490-670`](../../src/scripts.zig#L490-L670),
  [`src/scripts.zig:687-768`](../../src/scripts.zig#L687-L768)).
- The bridge exposes all seven documented commands and restricts them to
  `zero://app` and the loopback Vite origin
  ([`src/bridge.zig:32-34`](../../src/bridge.zig#L32-L34),
  [`src/bridge.zig:94-100`](../../src/bridge.zig#L94-L100),
  [`src/bridge.zig:196-202`](../../src/bridge.zig#L196-L202)).
- A single-server run expands the stored body, writes the audit entry, runs a
  bounded `bash -n -c` check on the selected server, then starts a tracked exec
  channel and updates the script's run metadata. Bash absence is reported
  separately from invalid syntax
  ([`src/bridge.zig:2446-2499`](../../src/bridge.zig#L2446-L2499),
  [`src/bridge.zig:2587-2631`](../../src/bridge.zig#L2587-L2631)).
- Broadcast state deduplicates server IDs, preserves selection order, permits
  at most four running servers, and retains at most 32 completed runs. Polling
  starts queued work and reads each channel with the caller's absolute cursor.
  Cancel marks queued items canceled and closes active channels, without
  claiming that channel close killed the remote process
  ([`src/broadcast.zig:15-30`](../../src/broadcast.zig#L15-L30),
  [`src/broadcast.zig:121-197`](../../src/broadcast.zig#L121-L197),
  [`src/bridge.zig:2729-2801`](../../src/bridge.zig#L2729-L2801),
  [`src/bridge.zig:2814-2842`](../../src/bridge.zig#L2814-L2842)).
- The manager owns the broadcast registry. Script output uses the same retained,
  per-consumer cursor protocol as SSH exec output, so one view does not drain
  another view's data
  ([`src/sessions.zig:925-945`](../../src/sessions.zig#L925-L945),
  [`src/sessions.zig:1613-1624`](../../src/sessions.zig#L1613-L1624)).

## Exact current bridge shapes

The Zig payload declarations are authoritative
([`src/bridge.zig:2381-2408`](../../src/bridge.zig#L2381-L2408)).

| Command | Request | Success result |
| --- | --- | --- |
| `oars.scripts.list` | `{}` | `{ok:true,scripts:Script[],recovery_error?}` |
| `oars.scripts.save` | `{script:ScriptInput}` | `{ok:true,script:Script}` |
| `oars.scripts.delete` | `{id}` | `{ok:true}` |
| `oars.scripts.run` | `{server_id,script_id,vars?:Record<string,{value:string,secret?:boolean}>}` | `{ok:true,channel:number}` |
| `oars.scripts.broadcast` | `{script_id,server_ids:string[],vars?:Record<string,{value:string,secret?:boolean}>}` | `{ok:true,run_id:number}` |
| `oars.scripts.broadcastPoll` | `{run_id,cursors?:Record<string,number>}` | `{ok:true,run_id,script_name,canceled,servers,done}` |
| `oars.scripts.broadcastCancel` | `{run_id}` | `{ok:true}` |

Each running or completed server entry can include
`{server_id,status,exit,error,cursor,gap,eof,data}`. The current serializer omits
the cursor fields for queued, failed, canceled, and skipped entries
([`src/bridge.zig:2747-2804`](../../src/bridge.zig#L2747-L2804)).

## Frontend that exists

- `ScriptsTab` loads the library, filters name/description/tags, renders run
  count and last-run metadata, and offers create, edit, delete, and one-server
  run controls. It polls the returned exec channel every 500 ms
  ([`frontend/src/ScriptsTab.tsx:17-46`](../../frontend/src/ScriptsTab.tsx#L17-L46),
  [`frontend/src/ScriptsTab.tsx:52-106`](../../frontend/src/ScriptsTab.tsx#L52-L106)).
- The view is available inside a per-server workspace, but Scripts is absent
  from `CONNECTION_VIEWS`, so the Run action can mount while that server is
  disconnected. The fleet-level Automation section also mounts it against
  `servers[0]`, without selecting or connecting that server in this branch
  ([`frontend/src/App.tsx:978-1007`](../../frontend/src/App.tsx#L978-L1007),
  [`frontend/src/App.tsx:1020-1027`](../../frontend/src/App.tsx#L1020-L1027),
  [`frontend/src/App.tsx:69-86`](../../frontend/src/App.tsx#L69-L86)).
- The command palette can navigate to each server's Scripts view, but it does
  not list or directly run saved scripts
  ([`frontend/src/App.tsx:753-766`](../../frontend/src/App.tsx#L753-L766)).

## Required corrections before frontend completion

1. **Fix the secret contract in the backend.** The stored definition uses
   `secret_default`, but `scriptsVars` trusts only the request's `secret` flag.
   The frontend types the field as `secret`, so a stored secret default is read
   as false and can reach audit/history without masking. The backend must treat
   `secret_default` as the minimum policy; a caller may promote a value to
   secret but must not demote it
   ([`src/scripts.zig:30-36`](../../src/scripts.zig#L30-L36),
   [`src/bridge.zig:2410-2424`](../../src/bridge.zig#L2410-L2424),
   [`frontend/src/bridge.ts:218-222`](../../frontend/src/bridge.ts#L218-L222),
   [`frontend/src/ScriptsTab.tsx:73-79`](../../frontend/src/ScriptsTab.tsx#L73-L79)).
2. **Use one strict frontend model.** Add `Script`, `ScriptInput`,
   `ScriptVariable`, `RunVars`, `BroadcastServer`, and `BroadcastPollResult` to
   `types.ts`. Remove the duplicate local interface and `any`. The save wrapper
   currently cannot send `variables`, while the editor has no detected-variable
   table, labels, or secret-default controls
   ([`frontend/src/bridge.ts:218-222`](../../frontend/src/bridge.ts#L218-L222),
   [`frontend/src/ScriptsTab.tsx:5-15`](../../frontend/src/ScriptsTab.tsx#L5-L15),
   [`frontend/src/ScriptsTab.tsx:136-150`](../../frontend/src/ScriptsTab.tsx#L136-L150)).
3. **Make basic CRUD valid.** The UI sends `color:"blue"`, but any nonempty
   backend color must start with `#`; a new script therefore fails validation.
   Use the six allowed product swatches as valid hex values and validate the
   exact allowed set in one layer
   ([`frontend/src/ScriptsTab.tsx:58-65`](../../frontend/src/ScriptsTab.tsx#L58-L65),
   [`src/scripts.zig:167-169`](../../src/scripts.zig#L167-L169)).
4. **Normalize timestamps.** Zig stores real-time nanoseconds, while the UI
   passes `last_run_at` directly to JavaScript `Date`, which expects
   milliseconds. Define one wire unit and convert at the boundary
   ([`src/bridge.zig:2531-2547`](../../src/bridge.zig#L2531-L2547),
   [`src/scripts.zig:423-430`](../../src/scripts.zig#L423-L430),
   [`frontend/src/ScriptsTab.tsx:118-122`](../../frontend/src/ScriptsTab.tsx#L118-L122)).
5. **Make single-run streaming cumulative and cancellable.** Each poll returns
   a delta from the requested cursor, but the UI replaces output with that
   delta. It also swallows poll errors, has no unmount cleanup, does not close a
   running channel, and does not show exit status. Append deltas, surface gaps
   and errors, stop timers on unmount/server change, and use
   `oars.ssh.closeChannel` for cancel
   ([`frontend/src/ScriptsTab.tsx:83-105`](../../frontend/src/ScriptsTab.tsx#L83-L105),
   [`frontend/src/bridge.ts:145-158`](../../frontend/src/bridge.ts#L145-L158)).
6. **Make the checked interpreter execute the command.** The bridge validates
   `bash -n -c <quoted command>`, but then passes the unwrapped expanded command
   to `execTracked`. The worker submits that text directly as an SSH `exec`
   request. A server whose account shell is not Bash can therefore accept Bash
   syntax in the check and interpret it differently during execution. Submit
   `bash -c <quoted command>` for the real run too, while keeping the human
   command as the redacted history and UI text
   ([`src/bridge.zig:2601-2622`](../../src/bridge.zig#L2601-L2622),
   [`src/sessions.zig:3430-3445`](../../src/sessions.zig#L3430-L3445),
   [`src/ssh.zig:680-692`](../../src/ssh.zig#L680-L692)).
7. **Add an authoritative preview step.** No current command returns the exact
   expanded command without creating a run. Reimplementing the Zig shell lexer
   in React can drift from the code that executes. Add a native prepare/preview
   contract that returns an immutable expansion or confirmation token, then
   make confirm consume that snapshot. This preserves the required
   preview-before-execution order and prevents a script edit between preview
   and confirm from changing what runs
   ([`src/bridge.zig:2446-2499`](../../src/bridge.zig#L2446-L2499),
   [`src/bridge.zig:2663-2687`](../../src/bridge.zig#L2663-L2687)).
8. **Implement the safe-broadcast frontend and wrappers.** There are no
   frontend wrappers for broadcast, poll, or cancel and no server/group
   selection, per-server expansion preview, destructive confirmation,
   cursor-map polling, side-by-side output, summary, or cancel UI
   ([`frontend/src/bridge.ts:218-223`](../../frontend/src/bridge.ts#L218-L223),
   [`frontend/src/ScriptsTab.tsx:108-163`](../../frontend/src/ScriptsTab.tsx#L108-L163)).
9. **Correct broadcast results.** `handleScriptsBroadcast` stores an empty
   script name, so poll returns `script_name:""`. EOF always changes a server
   to `done`, even when `exit` is nonzero; the contract's failed-exit summary
   therefore cannot rely on status. Pass the real script name and map nonzero
   exits to `failed`
   ([`src/bridge.zig:2674-2684`](../../src/bridge.zig#L2674-L2684),
   [`src/bridge.zig:2722-2727`](../../src/bridge.zig#L2722-L2727),
   [`src/bridge.zig:2795-2801`](../../src/bridge.zig#L2795-L2801)).
10. **Deduplicate before audit and bound admission.** The run state deduplicates
   IDs only after `scriptsPrepare` has already audited every raw request ID, so
   duplicate selections produce duplicate audit rows. The registry also has no
   cap on active/unpolled runs or server IDs per request. Deduplicate once
   before preview/audit and add request and active-run limits
   ([`src/bridge.zig:2493-2498`](../../src/bridge.zig#L2493-L2498),
   [`src/broadcast.zig:121-167`](../../src/broadcast.zig#L121-L167)).
11. **Use accessible, product-native dialogs.** The editor overlay has no
    `role="dialog"`, accessible name, description, focus trap, Escape handling,
    or focus restoration. Variable input and delete use browser `prompt` and
    `confirm`; a secret prompt is plain text. Build the edit, variable,
    broadcast selection, preview, destructive confirm, and delete flows on the
    established Oars modal pattern, with labeled fields, inline errors,
    `type="password"` for secrets, initial focus, trapped Tab, Escape when safe,
    and restored focus. Each approval must show the affected script and servers
    ([`frontend/src/ScriptsTab.tsx:73-79`](../../frontend/src/ScriptsTab.tsx#L73-L79),
    [`frontend/src/ScriptsTab.tsx:129-153`](../../frontend/src/ScriptsTab.tsx#L129-L153),
    [`frontend/src/MonitorTab.tsx:295-353`](../../frontend/src/MonitorTab.tsx#L295-L353),
    [`docs/DESIGN.md:201-203`](../DESIGN.md#L201-L203)).
12. **Add real preview fixtures and component tests.** `preview.html` has no
    `oars.scripts.*` cases; unmatched commands return only `{ok:true}`, while
    the page expects `scripts[]`. No frontend test targets `ScriptsTab`, and
    the script-specific class names have no definitions in `index.css`
    ([`frontend/preview.html:631-635`](../../frontend/preview.html#L631-L635),
    [`frontend/package.json:6-11`](../../frontend/package.json#L6-L11),
    [`frontend/src/ScriptsTab.tsx:109-160`](../../frontend/src/ScriptsTab.tsx#L109-L160)).

## Concurrency and security invariants to preserve

- Never persist run-time values. Store only variable definitions. Mask any
  value marked secret by either stored policy or run-time promotion in audit,
  command history, output snippets, preview recordings, and UI diagnostics.
- Keep broadcast concurrency at four unless the product contract changes.
  Queue progress must not depend on one view owning output; all views send
  their own absolute cursor maps.
- Do not call the expansion preview a dry run. It proves only the exact command
  Oars will submit. Each server still needs the backend `bash -n` check.
- A cancel request closes active SSH channels and prevents queued starts. It
  does not prove remote process termination. The worker sends channel EOF,
  closes the libssh2 channel, removes the entry, and frees retained output, so
  cancel must remain `cancel requested`; the UI must not wait for or claim a
  verified process kill
  ([`src/sessions.zig:1550-1560`](../../src/sessions.zig#L1550-L1560),
  [`src/sessions.zig:2526-2552`](../../src/sessions.zig#L2526-L2552)).
- The current syntax checks happen serially inside a poll handler and each can
  wait up to 30 seconds. A four-slot start can therefore block one bridge call
  for up to four sequential deadlines. Move readiness/syntax work to the
  server workers or make preparation incremental before widening fleet use
  ([`src/bridge.zig:2377-2379`](../../src/bridge.zig#L2377-L2379),
  [`src/bridge.zig:2729-2737`](../../src/bridge.zig#L2729-L2737)).

## Validation gate for the next implementation

Current checks run during this audit:

- `zig test src/scripts.zig` — 10/10 passed.
- `zig test src/broadcast.zig` — 4/4 passed.
- `./node_modules/.bin/tsc --noEmit` in `frontend/` — passed.
- `npm test -- --run` in `frontend/` — 59/59 passed, but none target scripts.

Before Spec 06 is marked complete, also run:

```sh
zig build
zig build test
scripts/integration-test.sh
npm --prefix frontend test
npm --prefix frontend run build
git diff --check
```

Add focused frontend tests for variable detection, stored-secret enforcement,
timestamp conversion, cumulative cursor output, poll cleanup, nonzero exits,
duplicate selection, destructive confirmation, preview/confirm snapshot
identity, cancel, stale responses, and 20+ server windowing. Add deterministic
preview states for empty, populated, corrupt recovery, validation error,
single-run success/failure/cancel, secret input, broadcast queued/running/mixed
results, unreachable server, output gap, destructive double-confirm, and
mobile/desktop light and dark layouts. The existing container test already
covers real run, injection neutralization, missing variables, syntax rejection,
two-server broadcast, audit redaction, run metadata, and cancel
([`src/integration.zig:1348-1507`](../../src/integration.zig#L1348-L1507)); extend
it for stored `secret_default`, duplicate-audit behavior, nonzero broadcast
exit, and the authoritative preview/confirm contract.
