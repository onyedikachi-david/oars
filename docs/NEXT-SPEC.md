# Next Spec Implementation Guide

> **Target:** Spec 11 — AI Terminal
>
> **Status:** Partial
>
> **Prepared:** 2026-08-31 against HEAD
> `48091a9aba80a0a0cd6d3fdb151d57090093fe03` and the full working tree

## Release posture

Implement the target in `docs/specs/11-ai-terminal.md`. That specification is
the product contract. This guide fixes the implementation order, ownership
boundaries, and evidence needed to change its status.

Spec 11 is substantially implemented, but it is not release-complete. The
current checkout has native provider transport and credentials, typed streams,
durable turns, validated proposals, backend approval, AI-specific tracked SSH
execution, verified process-group cancellation, restart classification, and the
complete React workflow. Unit, frontend, browser-fixture, and real SSH evidence
is recorded in `docs/research/spec-11-implementation-checklist.md`. Keep the
status Partial until the real operating-system credential lifecycle, live
OpenAI, pinned compatibility provider, forced process-restart, and remaining
accessibility gates pass on this checkout.

## Read before editing

Read this core set before the first code change:

- `docs/specs/README.md:1-100` for implementation truth, cursor streams,
  secrets, approvals, errors, shell quoting, cancellation, and session-worker
  ownership.
- `docs/specs/11-ai-terminal.md` for the complete target contract.
- `docs/research/spec-11-ai-terminal-current-state.md` for the source audit,
  architecture corrections, and primary-source findings.
- `docs/DESIGN.md:1-25`, `docs/DESIGN.md:109-126`, and
  `docs/DESIGN.md:169-203` for interface language, typography, state, focus,
  and responsive rules.

Read these source groups before their named slices:

- **Core and bridge:** `src/ai.zig`, the `oars.ai.*` registrations and
  handlers in `src/bridge.zig`, `src/main.zig:145-236`, and
  `src/runner.zig:401-575`.
- **Worker and execution:** `src/sessions.zig:1-8`,
  `src/sessions.zig:1651-1799`, `src/sessions.zig:3075-3185`,
  `src/history.zig:234-330`, `src/scripts.zig`, and
  `docs/specs/06-scripts.md:90-130`.
- **Current tests:** `src/integration_ai.zig`, the AI dispatcher tests in
  `src/main.zig`, `src/integration.zig`, and
  `scripts/integration-test.sh`.
- **Frontend:** `frontend/src/AiTab.tsx`, the AI types in
  `frontend/src/types.ts`, the AI bridge methods in
  `frontend/src/bridge.ts`, `frontend/src/App.tsx`,
  `frontend/src/test/mock-bridge.ts`, and `frontend/preview.html`.
- **Native credential boundary:** installed
  `@native-sdk/cli/src/runtime/api.zig:410-447`,
  `runtime/flow.zig:227-240`, `runtime/system_services.zig:89-108`,
  `runtime/core.zig:754-769`, and
  `platform/types.zig:239-241,2401-2403,2902-2914`. `build.zig:35`
  selects the installed package root.
- **Provider protocol:** read the official OpenAI Responses, streaming,
  Structured Outputs, conversation-state, authentication, data-control, and
  function-calling pages in the final source section before Slices 4 and 5.

## Preparation baseline and resolved P0 blockers

The pre-implementation audit found the following scaffolding. The current
implementation replaces these paths; this list remains as the historical
baseline that drove the work:

- `src/ai.zig` has one provider record, a prefix-based URL check, probe
  parsing, and a five-second context cache. It has no provider transport,
  adapter parser, event stream, journal, proposal, or coordinator.
- `src/bridge.zig` exposes only `oars.ai.context`,
  `oars.ai.provider.get`, `oars.ai.provider.set`, and
  `oars.ai.history`. `aiProbeOrCache` calls `Manager.execWait` with a
  20-second timeout from a bridge handler. This is a P0 main-thread violation.
- `oars.ai.history` reads generic `ssh.exec` audit rows. It cannot prove AI
  origin or user approval.
- `frontend/src/AiTab.tsx` uses `any`, accepts raw JSON that can include an
  API key, expects the wrong history shape, and has no turn or proposal flow.
  `frontend/src/App.tsx` can select `servers[0]` without explicit user
  choice.
- `src/integration_ai.zig` proves only metadata, context, generic SSH exec,
  and generic audit. It does not call a provider or the Native SDK credential
  service.
- The installed Native SDK has backend credential methods and
  `App.start_fn(context, *Runtime)`. Oars does not set that hook. The SDK does
  not document credential methods as safe on any thread and does not expose a
  native secret-entry field that Oars can use today. Native secure entry is a
  P0 implementation prerequisite.

## Fixed invariants

Review every slice against these rules:

1. **Native provider boundary.** Provider HTTP, TLS, authorization headers,
   server-sent event parsing, and provider retries stay in native Zig. The
   WebView Content Security Policy stays narrow.
2. **Native secret boundary.** A provider key enters through native secure
   input, persists as `ai:<provider_id>`, and is returned to React only as a
   status. It never enters bridge JSON, browser state, browser storage, or
   frontend traces.
3. **Runtime ownership.** `App.start_fn` installs a narrow credential facade
   in `bridge.Context`. Only the runtime thread calls it. A worker receives a
   bounded secret-bearing job buffer, never a raw `Runtime` pointer.
4. **No network on the bridge thread.** Bridge handlers validate bounded
   payloads, admit work, and copy snapshots. Provider workers own HTTP. The
   selected SSH session worker owns all libssh2 work.
5. **Durability before side effects.** A turn is journaled before a provider
   POST. Approval is journaled before SSH admission. A crash never causes an
   automatic provider retry or command execution.
6. **The model has no authority.** V1 sends no provider tools. Only one fully
   validated, durable proposal can reach the AI approval handler. A raw model
   event, restored record, or public `oars.ssh.exec` call cannot approve it.
   Spec 19 can present that proposal as an inline chat tool, but the same native
   approval and execution boundary remains authoritative.
7. **Frozen identity.** Approval binds proposal ID, revision, command SHA-256,
   server and connection identity, provider revision, expiry, and destructive
   acknowledgement under one lock.
8. **Independent streams.** Provider-test, context, and turn polling use
   absolute, non-destructive cursors. Each consumer can observe the same
   retained events. `dropped` reports its own gap.
9. **Honest cancellation.** Provider cancellation means that Oars stopped
   local network work; the provider can already have received the request.
   SSH cancellation is complete only after verified remote process-group
   termination.
10. **Bounded data.** Validate every identifier, request, response header, SSE
    event, structured result, log selection, journal, and event ring before
    unbounded allocation or persistence.
11. **Open release state.** Mock providers, direct generic SSH execution, and
    unit-only credential tests do not close an acceptance gate.

## Required file map

The public AI module remains `src/ai.zig`. Put the new implementation behind
that facade so `bridge.zig` does not own protocol or persistence logic.

| Path | Required ownership |
|---|---|
| `src/ai.zig` | Public domain types, bounds, coordinator facade, and re-exports. Remove old protocol assumptions after migration tests exist. |
| `src/ai/provider.zig` | Provider IDs and revisions, URL normalization, adapter-specific settings, atomic metadata store, and legacy metadata migration. |
| `src/ai/credentials.zig` | Runtime-thread facade, status-only results, bounded secret job buffer, and explicit overwrite. |
| `src/ai/transport.zig` | Native HTTP client, TLS, deadlines, redirect rejection, cancellation, request IDs, byte accounting, and redacted errors. |
| `src/ai/sse.zig` | Provider-neutral UTF-8 SSE framing with size bounds and arbitrary byte splits. |
| `src/ai/adapters.zig`, `src/ai/responses.zig`, `src/ai/chat_completions.zig` | Adapter interface and separate OpenAI Responses and Chat Completions grammars. |
| `src/ai/journal.zig` | Versioned append-and-sync records, replay, bounds, compaction, and recovery classification. |
| `src/ai/coordinator.zig` | Provider queue, context and turn operations, event rings, idempotency, cancellation, and terminal cleanup. |
| `src/ai/proposal.zig` | Strict result validation, destructive classification, edit revisions, hashes, expiry, and prepare-to-commit checks. |
| `src/main.zig` | `App.start_fn` and `App.stop_fn` wiring. Do not add a worker-visible runtime pointer. |
| `src/bridge.zig` | Exact bounded request parsing and response serialization for the wire contract below. No provider JSON parser or network wait. |
| `src/sessions.zig`, `src/history.zig` | AI-specific tracked execution, stable operation identity, process-group cancellation, completion reconciliation, and `history_kind = "ai"`. |
| `src/integration_ai.zig`, `src/integration.zig` | Native provider fixture, SSH container flow, restart, cancellation, audit, and history evidence. |
| `fixtures/ai/destructive.json` | One shared destructive-command fixture set consumed by Zig and React tests. Add it to package paths if the build needs it. |
| `frontend/src/features/ai/` | Typed reducer, hooks, provider setup, disclosure, thread, proposal, output, error, and recovery components. |
| `frontend/src/AiTab.tsx` | Thin feature entry point. It must not own protocol parsing or secret state. |
| `frontend/src/types.ts`, `frontend/src/bridge.ts` | Exact discriminated wire unions and bridge wrappers. |
| `frontend/src/App.tsx` | Explicit active-server handoff and script-editor draft handoff. |
| `frontend/src/test/mock-bridge.ts`, `frontend/preview.html` | Contract-accurate mocks and deterministic state fixtures. |

If native secure entry requires a Native SDK change, land and version that
dependency before Slice 3 can finish. Do not keep an untracked global SDK edit
as release evidence. An Oars-owned native platform adapter is acceptable only
after a separate design review and the same cross-platform tests.

## Ordered implementation slices

Work in this order. A slice is complete only when its completion condition is
true. Keep later UI work behind typed mocks until the owning backend slice is
complete.

### Slice 0 — Freeze the contract and baseline

1. Record `git status --short`, the HEAD commit, and every tracked and
   untracked file. Preserve unrelated work.
2. Build a requirement-to-test checklist from Spec 11 Sections 5 through 12.
   Map each bridge command, state, bound, and release gate to one owning test.
3. Replace the old AI mock shapes with failing contract fixtures for the new
   names and tagged unions. Do not add permissive `any` fields to make the
   fixtures compile.
4. Run the current validation commands and record existing failures. This is a
   baseline, not release evidence.

**Complete when:** every Spec 11 requirement has one planned owner and test,
and baseline failures are separated from changes made for Spec 11.

### Slice 1 — Land domain types and durable provider metadata

1. Define the shared bounds, IDs, revisions, error codes, provider types,
   operation states, event envelope, proposal type, and turn state in Zig.
   Mirror them as TypeScript discriminated unions.
2. Replace the single provider object with a versioned store of at most 16
   providers. Each provider has a stable random ID and monotonic revision.
3. Normalize the configured API prefix. For OpenAI, the base is
   `https://api.openai.com/v1`; adapters append `/responses` or
   `/chat/completions`. Reject user information, fragments, query data,
   control bytes, and non-loopback HTTP.
4. Write metadata through a mode-0600 sibling temporary file, sync it, and
   rename it atomically. Quarantine corrupt files without silently replacing
   them.
5. Migrate a valid legacy provider record once. Generate its provider ID and
   mark its test state `stale`. Do not claim that a legacy
   `ai:<base_url>` secret moved; the new native path requires the user to
   configure `ai:<provider_id>`.
6. Add idempotent `provider.list`, `provider.save`, and
   `provider.delete` core operations with expected-revision checks. A
   provider edit or credential change makes its test stale.

**Complete when:** provider unit tests prove validation, legacy migration,
atomic replacement, mode 0600, quarantine, revision conflicts, operation-ID
deduplication, the 16-provider bound, and the absence of key fields.

### Slice 2 — Remove the blocking context path

1. Replace `oars.ai.context` with `context.get`, `context.refresh`,
   `context.poll`, and `context.cancel`.
2. Make `context.get` a cache snapshot only. It must not enqueue hidden work.
3. Make `context.refresh` register a bounded operation and queue the probe on
   the selected session worker. Use an asynchronous outcome pattern; do not
   call `execWait` or wait for SFTP from the bridge.
4. Publish context operation events through the common cursor ring. Preserve
   partial monitor data and a typed probe error.
5. Return log metadata only. Read one selected log tail during
   `turn.start`, after disclosure and on worker-owned I/O.
6. Add a responsiveness test that holds a context probe for 20 seconds while
   unrelated bridge commands complete.

**Complete when:** no AI bridge handler can wait on SSH, context cursors are
independent, cancel is idempotent, and the responsiveness test passes.

### Slice 3 — Establish native credential and secure-entry ownership

1. Set `App.start_fn` in `src/main.zig`. It receives `*Runtime` from the
   installed SDK and installs a narrow set/get/delete facade in
   `bridge.Context`.
2. Keep the facade runtime-thread-bound. The provider worker cannot hold or
   call `*Runtime`.
3. Add a native secure-entry sheet or land the required Native SDK service.
   `credential.configure` returns only
   `configured|canceled|denied|unavailable`. There is no React text field or
   bridge payload for the key.
4. Implement `credential.status` with a bounded native scratch buffer.
   Return only status, then overwrite the scratch buffer.
5. For provider admission, validate the operation first, read at most 4096 key
   bytes into the secret-bearing request job, and queue it. The worker
   overwrites every copy, including the authorization-header buffer, on all
   success, error, timeout, and cancel paths.
6. Set `App.stop_fn` to stop admission, cancel and join provider workers,
   overwrite queued secret buffers, clear the facade, and only then let the
   runtime stop.

**Complete when:** native integration tests configure, replace, detect, use,
and delete a key on the correct thread; shutdown order is deterministic; and a
secret scan finds no key in React state, bridge JSON, traces, files, journals,
audit, history, or errors.

### Slice 4 — Prove the native transport and SSE parser

1. Build a deterministic local HTTP/TLS fixture. It must fragment bytes at
   arbitrary positions, delay headers and body data, return 401, 429, and 500,
   attempt redirects, close mid-event, and observe cancel cleanup without
   printing the key.
2. Implement the native request state machine with 10-second connect,
   30-second first-byte, 30-second idle, and 120-second total deadlines.
3. Disable redirects for authenticated POST requests. Bind the credential to
   the reviewed normalized origin. Do not retry after any request byte can
   have reached the provider.
4. Enforce the request, header, event, structured-output, and error-body bounds
   in **Fixed bounds** before accumulation.
5. Implement UTF-8 SSE framing for CRLF and LF, comments, blank-event
   termination, multiple `data:` lines, and every possible byte split.
6. Generate `X-Client-Request-Id` and capture `x-request-id` when present.
   Keep prompts, context, response bodies, and authorization values out of
   diagnostic logs.

**Complete when:** transport and SSE unit tests pass, the local fixture proves
timeouts, cancel, redirect rejection, bounds, redaction, and no automatic POST
retry, and packaged TLS trust is exercised on each supported desktop platform.

### Slice 5 — Implement explicit provider adapters and provider test

1. Define the adapter interface:

   ```text
   buildRequest(turn, context, local_items) -> request
   acceptStatus(status, headers) -> stream | typed error
   feedBytes(bytes) -> provider events
   finish() -> one terminal result | protocol error
   classifyRetry(bytes_sent, response_started, error) -> never | explicit_only
   ```

2. Implement `openai_responses` first. Send `stream:true`,
   `store:false`, `background:false`, and the strict
   `text.format` schema in Spec 11 Section 6.3. Request
   `reasoning.encrypted_content` in `include` so a stateless later turn can
   replay an encrypted reasoning item when OpenAI returns one. Do not send
   `previous_response_id`, a Conversation ID, or tools.
3. Parse typed Responses lifecycle, output-item, text, refusal, incomplete,
   failed, and error events. Ignore unknown bounded event types. Reject a
   malformed known event, inconsistent item identity, duplicate terminal
   state, or missing terminal state.
4. Implement `openai_chat_completions` as a separate compatibility grammar.
   It supports only an explicitly tested instruction role and
   `json_schema|json_object` mode. It has no prompt-only JSON fallback.
5. Keep static policy in the developer message. Put the user question and all
   host, monitor, process, and log values in labeled user data.
6. Implement Provider Test through the chosen route, model, stream grammar,
   instruction role, and schema mode. Warn about quota before admission.
   Persist the tested provider revision and result, never the key.
7. Treat any model function call, shell call, computer call, MCP call, or
   built-in tool call as a v1 protocol error.

**Complete when:** recorded Responses fixtures cover command, question,
refusal, incomplete, failed, error, reasoning items, and unknown events; Chat
Completions fixtures cover each declared mode; and one pinned Ollama or vLLM
version passes the exact compatibility test.

### Slice 6 — Add the durable coordinator, journal, and turn stream

1. Add bounded registries for context operations, provider tests, threads,
   turns, and event rings. Permit two active provider requests in total and one
   per thread.
2. Append and sync `turn_queued` before a provider job can send. Append and
   sync `provider_request_started` with the client request ID before the
   first request byte.
3. Persist the user message, validated assistant result, and adapter-owned
   continuation items needed by `store:false`. Store returned
   `reasoning.encrypted_content` as opaque adapter data. Persist log selection,
   byte count, and hash, but not raw log content by default.
4. Convert provider events to the versioned domain union below. Do not
   send raw provider JSON to React. Coalesce progress to ten events per second.
5. Append and sync a validated proposal before publishing `proposal.ready`.
   Token deltas can update progress but cannot create visible assistant text
   or a Run action.
6. Implement thread list, get, delete, turn start, poll, and cancel. Bind an
   existing thread to its server, provider adapter, and model.
7. Compact through a mode-0600 sibling file, sync, and atomic rename. Preserve
   active proposals and executions. If required continuation items exceed
   512 KiB, require a new thread instead of removing protocol items.

**Complete when:** journal replay, a truncated final record, corrupt middle
record, compaction interruption, bounds, two independent poll consumers,
operation-ID retry, and restart state tests pass without a duplicate POST.

### Slice 7 — Freeze proposals and admit exact AI execution

1. Put the exact strict proposal schema from Spec 11 in one Zig-owned
   constant. Validate the discriminator, one non-null payload, UTF-8, NUL,
   field bounds, one proposal-bearing message, and one structured result.
2. Compute `command_sha256`, local destructive state, model destructive
   state, server and connection identity, provider revision, and a ten-minute
   expiry. Persist the proposal before the UI can render it.
3. Make `proposal.edit` create a new revision and rerun all local checks. The
   former revision becomes unusable.
4. Make `proposal.run` check ID, revision, hash, expiry, server and connection
   identity, provider revision, proposal state, and destructive
   acknowledgement under one lock.
5. Append and sync `approval_recorded`, then write one `ai.approved` audit
   row, then admit the exact command to tracked SSH execution with the same
   operation ID and `history_kind = "ai"`.
6. Make admission idempotent. A repeated Run returns the first admission
   result and never starts another channel. Generic `oars.ssh.exec` remains
   outside this approval path.
7. Record exit, duration, and a bounded redacted output sample against the
   same operation. AI thread history must exclude generic SSH rows.

**Complete when:** tests reject stale revisions, wrong hashes, server or
connection changes, provider edits, expiry, missing destructive
acknowledgement, interactive sudo, and duplicate Run; one approved container
command completes with matching proposal, audit, channel, and history identity.

### Slice 8 — Finish cancellation and restart recovery

1. Add a tested AI execution wrapper that starts and identifies a remote
   process group without changing the frozen user command. The wrapper is
   fixed transport code. It passes the command through the shared shell-quote
   path and does not rewrite it; the proposal hash and audit record identify
   the user-visible command.
2. On execution cancel, record `cancel_requested`, signal the group, escalate
   within a bound when required, and verify termination, including child
   processes. Channel close is cleanup, not proof.
3. Resolve cancel-versus-complete races under one lock. Exactly one terminal
   record wins and every capacity slot is released once.
4. Apply the **Recovery matrix** during journal replay. Never restart
   provider or SSH work. Reconcile a live tracked channel when possible and
   mark an absent or ambiguous execution `recovery_required`.
5. Keep terminal records and output readable through the retention bounds
   after cancel, disconnect, and restart.

**Complete when:** forced restart at every non-terminal state causes no
duplicate POST or command, hard cancel verifies a child process is gone, and
uncertain execution remains `cancel_requested|recovery_required`.

### Slice 9 — Build the typed React workflow

1. Replace the current `AiTab` data flow with a reducer over the exact tagged
   unions. Remove AI-path `any`, raw provider JSON input, provider parsing,
   partial-JSON rendering, and `servers[0]` fallback.
2. Build explicit server selection, provider setup and test, credential status,
   context selection and disclosure, thread list, composer, stream progress,
   question/refusal/error states, proposal cards, edit, approval, output,
   cancel, recovery, and clear-thread flows.
3. Keep server, SSH user, provider origin, model, and credential state visible
   above the composer and on every proposal.
4. Poll with caller-owned cursors. Ignore stale responses by stream ID and
   sequence. Report `dropped`; never reset a shared backend cursor.
5. Use status text plus an icon, accessible dialogs, focus return, keyboard
   actions, command-only monospace, light and dark themes, and narrow layouts.
6. Add deterministic `?ai=` fixtures for: `no-server`, `no-provider`,
   `credential-missing`, `context-disclosure`, `provider-test-running`,
   `provider-auth-failed`, `streaming`, `question`, `refusal`,
   `proposal-safe`, `proposal-destructive`, `proposal-edited`,
   `execution-running`, `cancel-requested`, `recovery-required`,
   `summary-disclosure`, and `long-command`.

**Complete when:** reducer, bridge, component, accessibility, stale-poll,
cursor-gap, explicit-server, and fixture tests pass with production wire types
and no key value exists in frontend code or test payloads.

### Slice 10 — Add summary disclosure and save as script

1. Make post-run summary an explicit new provider turn. Show the exact bounded
   command-output cursor range before admission. A failed summary does not
   change the command result.
2. Make **Open in script editor** pass the exact approved or edited command as
   a draft through `App`. The user reviews name, variables, and destructive
   state before `oars.scripts.save`.
3. Test summary skip, cancel, provider failure, output gaps, script draft,
   script save failure, and a successful saved-script run.

**Complete when:** no command output leaves the computer without its own
disclosure and the saved script uses the Spec 06 review and execution path.

### Slice 11 — Collect release evidence

1. Run every command in **Exact validation commands** on one fixed checkout.
2. Run one current OpenAI Responses request through native credentials with
   `store:false`, strict Structured Outputs, typed streaming, client and
   provider request IDs, and a harmless approved container command.
3. Run one pinned Ollama or vLLM compatibility adapter separately.
4. Force provider cancel, verified remote process-group cancel, disconnect,
   and restart at each non-terminal state.
5. Inspect all deterministic UI fixtures at desktop and narrow widths in light
   and dark themes. Record browser, viewport, date, and result.
6. Scan application data, logs, traces, journal, audit, history, bridge
   payloads, browser state, and error output for the test key.

**Complete when:** every item in **Open release gates** has dated evidence from the
same checkout. Only then update Spec 11, the feature index, and this guide in
the implementation change.

## Wire contract and bounds

The command names below replace the current `oars.ai.context`,
`provider.get`, `provider.set`, and generic `ai.history` scaffold. Remove
the old commands after production callers and tests migrate. Do not keep an
alias that preserves browser-side secrets, synchronous context work, or generic
SSH history.

### Common rules

- Timestamps are integer epoch milliseconds. Do not send epoch nanoseconds as
  a JavaScript `number`.
- Revisions, event sequences, and cursors are integers.
- An `operation_id` is 1 to 64 ASCII letters, digits, dots, colons,
  underscores, or hyphens. Reuse it only to retry the same mutation.
- A user failure is `{ok:false, code, error}`. Stable codes are
  `invalid_argument`, `not_found`, `conflict`, `stale_revision`,
  `not_connected`, `credential_missing`, `provider_untested`, `busy`,
  `limit_exceeded`, `provider_auth`, `provider_rate_limited`,
  `provider_timeout`, `provider_protocol`, and `recovery_required`.
- Parse into bounded Zig structs before admission. TypeScript wrappers return
  the exact result union; they do not cast through `any`.

### Provider and credential commands

```text
oars.ai.provider.list {}
  -> {ok, providers:[ProviderPublic]}

oars.ai.provider.save {operation_id, provider, expected_revision?}
  -> {ok, provider:ProviderPublic}

oars.ai.provider.delete {operation_id, provider_id, expected_revision}
  -> {ok}

oars.ai.provider.test {operation_id, provider_id, expected_revision}
  -> {ok, operation_id, state}

oars.ai.provider.testPoll {operation_id, cursor, rewind?}
  -> EventPoll

oars.ai.provider.testCancel {operation_id}
  -> {ok, state}

oars.ai.credential.configure {operation_id, provider_id}
  -> {ok, status:"configured"|"canceled"|"denied"|"unavailable"}

oars.ai.credential.status {provider_id}
  -> {ok, status:"configured"|"missing"|"denied"|"unavailable"}

oars.ai.credential.delete {operation_id, provider_id}
  -> {ok, status:"missing"}
```

`ProviderDraft` is:

```text
{id?, name, adapter, base_url, model, instruction_role?, structured_output?}
```

`ProviderPublic` adds `revision`, `tested_at_ms?`, and `test_status` and
never contains a key. `adapter` is `openai_responses` or
`openai_chat_completions`. `test_status` is
`untested|passed|failed|stale`. The Chat Completions adapter requires an
explicit `developer|system` instruction role and
`json_schema|json_object` structured-output mode. Responses does not accept
those compatibility switches.

### Context commands

```text
oars.ai.context.get {server_id}
  -> {ok, state, context?, stale, updated_at_ms?}

oars.ai.context.refresh {operation_id, server_id}
  -> {ok, operation_id, state}

oars.ai.context.poll {operation_id, cursor, rewind?}
  -> EventPoll

oars.ai.context.cancel {operation_id}
  -> {ok, state}
```

`context.get` is cache-only. A context snapshot contains the selected server
ID, OS and host data when available, the monitor snapshot, active-log
metadata, partial status, typed errors, and `updated_at_ms`. It contains no
log bytes. A stale snapshot never starts a hidden refresh.

### Thread, turn, and proposal commands

```text
oars.ai.thread.list {server_id?, limit}
  -> {ok, threads:[ThreadSummary]}

oars.ai.thread.get {thread_id}
  -> {ok, thread, turns, turns_start, turn_count, active_proposal?}

oars.ai.thread.delete {operation_id, thread_id, expected_revision}
  -> {ok}

oars.ai.turn.start {
  operation_id, thread_id?, server_id, provider_id,
  expected_provider_revision, message,
  context_selection:{os, monitor, log:{source_id, tail_bytes}?}
} -> {ok, thread_id, turn_id, state}

oars.ai.turn.poll {turn_id, cursor, rewind?}
  -> EventPoll

oars.ai.turn.cancel {turn_id}
  -> {ok, state}

oars.ai.turn.summarize {
  operation_id, thread_id, execution_id,
  output_selection:{start_cursor, end_cursor}
} -> {ok, turn_id, state}

oars.ai.proposal.edit {
  operation_id, proposal_id, expected_revision, command
} -> {ok, proposal:Proposal}

oars.ai.proposal.run {
  operation_id, proposal_id, expected_revision,
  command_sha256, destructive_warning_ack
} -> {ok, execution_id, channel, state}

oars.ai.proposal.cancel {
  operation_id, proposal_id, expected_revision
} -> {ok, state:"canceled"}
```

`ThreadSummary` is `{id, revision, server_id, provider_id, model, title,
state, turn_count, updated_at_ms}`. A thread stores the provider adapter and
model snapshot used for continuation. A mismatch requires a new thread.
`thread.get` returns all turns when they fit the bridge response bound. If the
full detail is too large, it returns the largest latest-turn suffix that fits;
`turns_start` is the zero-based index of that suffix and `turn_count` is the
durable total. It returns `limit_exceeded` if the latest turn cannot fit.

`TurnState` is:

```text
queued | collecting_context | requesting | streaming | validating |
awaiting_approval | approved | executing | summarizing | completed | failed |
cancel_requested | canceled | interrupted | recovery_required
```

`Proposal` is:

```text
{id, turn_id, revision, server_id, provider_id, provider_revision,
 context_hash, command, command_sha256, explanation,
 model_destructive, local_destructive, needs_sudo,
 created_at_ms, expires_at_ms, state}
```

Use the strict JSON Schema in `docs/specs/11-ai-terminal.md:350-375` as the
single model-output schema. The Zig validator is authoritative. A question has
one non-null question and a null command. A command has one non-null command
and a null question. Refusal, incomplete output, an extra schema field,
multiple proposal-bearing messages, multiple structured results, or invalid
UTF-8 cannot create a proposal.

### Versioned event contract

`EventPoll` is:

```text
{ok, stream_id, cursor, dropped, finished, state, events:[
  {version:1, sequence, stream_id, type, payload}
]}
```

For cursor `C`, return retained events with `sequence >= C`. The response
cursor is one past the last returned sequence. If `C` is before the retained
start, begin at retained start and set `dropped` to the gap. `rewind:true`
begins at retained start. Polling never removes events.

Provider-test event types are:

```text
provider.test_started
provider.test_succeeded
provider.test_failed
provider.test_canceled
```

Context event types are:

```text
context.refresh_started
context.ready
context.failed
context.canceled
```

Turn event types are:

```text
turn.started
context.ready | context.failed
provider.request_started
provider.response_created
provider.progress
proposal.ready
question.ready
provider.refusal
turn.incomplete
turn.failed
turn.cancel_requested
turn.canceled
turn.completed
```

Required payload fields are:

- `provider.request_started`: `{client_request_id}`.
- `provider.response_created`: `{provider_request_id?}`.
- `provider.progress`: `{phase, received_bytes}`; no partial proposal text.
- `proposal.ready`: `{proposal}`.
- `question.ready`: `{question, explanation}`.
- `provider.refusal`: `{reason?}`, with the reason bounded and treated as
  untrusted text.
- `turn.incomplete|turn.failed`: `{code, error, retry:"explicit"|"never"}`.
- Terminal cancellation and completion events carry the final state and
  timestamp.

Provider SSE names and raw JSON stop inside the adapter. Command output remains
in `oars.ssh.poll`; the AI event ring does not duplicate terminal bytes.

### Fixed bounds

Enforce these before allocation, network use, or persistence:

| Item | Bound |
|---|---:|
| Providers | 16 |
| Threads | 100 |
| Turns per thread | 50 |
| User message | 16 KiB |
| Command | 64 KiB |
| Explanation or question | 8 KiB |
| Selected log tail | 64 KiB |
| Provider request body | 128 KiB |
| Response headers | 64 KiB |
| One SSE event | 256 KiB |
| Accumulated structured output | 128 KiB |
| Retained provider error body before redaction | 8 KiB |
| Domain events per turn | 1024 |
| Domain event bytes per turn | 1 MiB |
| Adapter continuation items per thread | 512 KiB |
| Active provider requests | 2 total, 1 per thread |
| Credential secret | 4096 bytes, from the Native SDK bound |

Whichever event-ring bound is reached first controls retention. Compaction
removes the oldest terminal turns first and never removes an active proposal
or execution.

## Native and worker boundaries

### Runtime credential flow

1. The runtime constructs `App` and calls `App.start_fn(context, *Runtime)`
   during `app_start`.
2. Oars stores a narrow facade in `bridge.Context`. The facade exposes only
   set, get, and delete for the fixed service and account naming rules.
3. Native secure entry sends the secret directly to
   `Runtime.setCredential`. React sees only the terminal status.
4. A provider admission handler calls `Runtime.getCredential` on the runtime
   thread into a fixed request-job buffer. It queues the job and returns.
5. The provider worker creates the authorization header, sends the request,
   and overwrites all secret-bearing buffers on every exit.
6. `App.stop_fn` stops new admission, cancels and joins workers, overwrites
   queued buffers, and clears the facade before runtime teardown.

`credential.status` may use `getCredential` with a scratch buffer only to
distinguish configured from missing. It must overwrite the buffer and return
no length, prefix, or secret value.

### Provider worker flow

The bridge thread owns payload admission only. The coordinator worker owns
journal writes, provider queues, and published operation state. A provider
worker owns one HTTP client and adapter parser for the request. No worker calls
the Native SDK runtime.

The configured base URL is an API prefix. Normalize it once and retain its
origin and path prefix separately. The adapter appends `/responses` or
`/chat/completions`. Revalidate the effective URL before send. Authenticated
POST requests do not follow redirects.

After any request byte can reach a provider, network failure is ambiguous.
Publish an explicit retry action that creates a new operation. Do not retry in
the transport or coordinator.

### SSH worker flow

Context probes, selected log reads, command admission, output, process-group
signals, and termination checks stay on the selected session worker. The AI
coordinator receives copied outcomes. Bridge polling only reads published
state.

The AI approval handler calls a dedicated internal execution entry point. It
does not invoke the public bridge command `oars.ssh.exec`. The internal entry
point receives the already frozen command and the stable AI operation
identity.

### Provider tools

Spec 11 v1 sends no `tools` field. A returned function, shell, computer, MCP,
web-search, file-search, or code-interpreter call is a protocol error. Keep
future `call_id`, tool-output, and parallel-call work outside this
implementation.

## Journal, recovery, and cancellation

### Local files

- `<data>/ai.json` stores versioned provider metadata only.
- `<data>/ai_journal.jsonl` stores thread, turn, proposal, approval,
  execution, and recovery transitions.
- The operating-system credential store holds `ai:<provider_id>`.
- Command history and audit remain in the Spec 15 stores. The AI journal
  references their stable operation ID; it does not copy their byte streams.

Both AI files use mode 0600. Provider metadata and journal compaction use a
sibling temporary file, file sync, and atomic rename. The journal append path
syncs each state transition before the related side effect can start.

### Record envelope and write order

Use one versioned envelope:

```text
{version:1, sequence, timestamp_ms, kind, operation_id?,
 thread_id?, turn_id?, proposal_id?, execution_id?, payload}
```

Record only state transitions and durable continuation data. Do not append each
token delta. Required record kinds are:

```text
thread_created | thread_deleted
turn_queued | context_collected
provider_request_started | provider_result | provider_interrupted
proposal_ready | proposal_edited | proposal_canceled
approval_recorded | execution_admitted | execution_finished
turn_terminal | recovery_marked
```

The ordering rules are:

1. `turn_queued` is durable before provider job admission.
2. `provider_request_started`, including the client request ID, is durable
   before the first request byte.
3. `provider_result` and all adapter continuation items are durable before a
   question or proposal event.
4. `proposal_ready|proposal_edited` is durable before React can approve its
   revision.
5. `approval_recorded` is durable before audit and SSH admission.
6. `execution_admitted` records the channel identity immediately after the
   session worker accepts it.
7. `execution_finished` and `turn_terminal` close the same operation.

A truncated final JSON line is recoverable: keep the valid prefix, quarantine
the tail, and publish a recovery warning. A corrupt complete record in the
middle makes the journal unavailable for mutation. Quarantine it and require
user-visible recovery; do not infer state or execute anything.

### Recovery matrix

| State found on startup | Required result |
|---|---|
| `queued` or `collecting_context` | Mark `interrupted`. Do not restart. |
| `requesting`, `streaming`, or `validating` | Mark `interrupted`. A retry is a new provider operation because the first request can have been received or billed. |
| `awaiting_approval` | Restore the exact proposal only when it is unexpired and all bound identities still match. Otherwise expire it. |
| `approved` without `execution_admitted` | Mark `recovery_required`. Do not execute. |
| `executing` with a live tracked channel | Reattach observation to that channel. Do not create a second channel. |
| `executing` without a live tracked channel | Mark `recovery_required`. Do not rerun. |
| `summarizing` | Mark the summary `interrupted`; keep the command result terminal. |
| Terminal state | Keep it terminal and idempotent. |

Thread deletion removes local conversation and adapter continuation items. It
does not erase audit or command history. Provider deletion and credential
deletion remain separate actions.

### Cancellation matrix

| Stage | Cancel action | Honest result |
|---|---|---|
| Queued context or provider job | Remove it before worker admission and append terminal cancellation. | `canceled`; no network side effect started. |
| Active provider request | Set the cancel flag and close the local request/stream. Resolve a completion race under the coordinator lock. | `canceled` means local work stopped. The UI still states that the provider can have received and billed it. |
| Awaiting approval | Mark the proposal unusable and append `proposal_canceled`. | `canceled`; no remote command exists. |
| Active SSH execution | Append `cancel_requested`, signal the tracked process group, escalate when required, verify group and children, then close the channel. | `canceled` only after verification. Otherwise remain `cancel_requested` or become `recovery_required`. |
| Disconnect during execution | Preserve channel and operation evidence, then reconcile on reconnect or restart. | Never infer success, failure, or cancellation from disconnect alone. |

Poll calls observe this state. They do not advance cancellation, start cleanup,
or finalize a job. Worker completion must release request, operation, and
session capacity exactly once even when the frontend stops polling.

## Frontend state and fixtures

The AI feature reducer owns one explicit state for each of these groups:

- **Target:** no server, selected server, disconnected server, and server
  changed while a proposal is visible.
- **Provider:** none, untested, test quota warning, testing, passed, stale,
  authentication failed, rate limited, protocol mismatch, canceled, missing
  key, denied key access, and credential service unavailable.
- **Context:** cache missing, loading, fresh, stale, partial, failed, selection
  changed, and disclosure required.
- **Turn:** queued, collecting context, requesting, streaming, validating,
  question, refusal, incomplete, retryable failure, terminal failure,
  cancel requested, canceled, interrupted, and recovery required.
- **Proposal:** ready, edited, stale, expired, destructive, needs sudo,
  approving, executing, used, and canceled.
- **Execution:** running, output gap, exit success, exit failure, connection
  lost, cancel requested, canceled, and recovery required.
- **Follow-up:** summary disclosure, running, skipped, failed, and completed;
  script draft, saved, and save failed.

The reducer accepts domain events only when `stream_id` matches and
`sequence` is newer than the last applied event. A delayed poll response
cannot move state backward. An event gap is visible and triggers a snapshot
refresh; it does not reset the backend cursor.

React never owns a provider parser, command hash, destructive authority,
credential value, or execution admission decision. The proposal card renders
the backend proposal verbatim. Edit sends a new command to Zig and waits for a
new revision.

The deterministic preview must cover every `?ai=` fixture named in Slice 9.
Each fixture uses a fixed clock and contract-accurate bridge responses. Add
tests that fail when the mock omits a required union member or returns a legacy
`entries`, `openai_compatible`, or raw-config shape.

## Verification matrix

### Zig unit and contract tests

| Area | Required cases |
|---|---|
| Provider metadata | Stable random IDs, revision conflicts, idempotent mutations, legacy migration, no secret migration claim, atomic write, mode 0600, quarantine, and 16-provider bound. |
| URL and transport policy | HTTPS, approved IPv4 and IPv6 loopback HTTP, user information, fragment, query, path-prefix joining, redirect rejection, DNS, TLS, timeouts, request byte accounting, no retry, and redacted error bodies. |
| SSE | Every byte split, CRLF and LF, comments, multiple data lines, invalid UTF-8, oversized line and event, cancel during a partial event, and terminal framing. |
| Responses adapter | Command, question, reasoning item, refusal, incomplete, failed, error, unknown bounded event, malformed known event, inconsistent item identity, duplicate terminal, missing terminal, and strict schema. |
| Chat adapter | Each declared instruction role and structured mode, fragmented chunks, terminal marker, invalid JSON, unsupported mode, and explicit-only retry. |
| Events | Independent cursors, rewind, gap count, byte and count retention, stale consumer, coalesced progress, unknown frontend event rejection, and terminal snapshot. |
| Proposal | Discriminator, field bounds, NUL, multiple results, hash, expiry, destructive fixtures, edit reclassification, wrong server or connection, provider revision, warning acknowledgement, interactive sudo, and double Run. |
| Journal | Write-before-side-effect order, sync failures, replay, truncated tail, corrupt middle, compaction crash, retention, operation idempotency, and every recovery row. |
| Cancellation | Before-send cancel, active HTTP cancel, completion race, proposal cancel, process-group signal and escalation, verified child exit, uncertain result, and exactly-once slot release. |

### Native credential integration

Test the real installed platform service, not an in-memory substitute:

- `App.start_fn` installs the facade before bridge use and `stop_fn` clears
  it after workers stop.
- Configure, replace, status, get, and delete work through native entry.
- Missing, denied, unavailable, oversized, and shutdown-race cases are typed.
- Runtime calls stay on the permitted thread.
- Request and authorization-header buffers are overwritten after success,
  error, timeout, cancel, and shutdown.
- A test key is absent from bridge inspectors, React, browser storage, app
  data, journal, audit, history, logs, traces, crash output, and error text.

### Local provider integration

The deterministic fixture must:

- receive the exact Responses and Chat routes
- verify that authorization is present without writing its value
- verify `store:false`, `background:false`, strict `text.format`, and no
  tools for Responses
- fragment SSE across every parser boundary used by the test
- exercise question, refusal, incomplete, invalid schema, 401, 429, 500,
  redirect, idle timeout, body drop, and cancel
- prove that no POST is retried after send
- return fixed request IDs for audit assertions

### SSH container integration

Extend `src/integration_ai.zig` and the real
`scripts/integration-test.sh` harness to prove:

1. Explicit server and provider selection.
2. Worker-owned context refresh and bounded selected log disclosure.
3. Fixture ask, full stream validation, and durable proposal.
4. Edit before Run, destructive reclassification, wrong hash, stale revision,
   server switch, provider edit, expiry, and double Run.
5. Exact approved command, `history_kind = "ai"`, `ai.approved` audit,
   streamed output, real exit, and no generic SSH row in AI thread history.
6. Provider cancel, verified remote process-group cancel with a child process,
   disconnect, and restart at every non-terminal state.
7. No duplicate provider request or remote command after recovery.
8. Summary disclosure and save-as-script round trip.

### React and manual verification

Add focused reducer, bridge, component, and app-level tests for every state in
the frontend section. Include cursor gaps, stale responses, target changes,
long values, focus return, Escape behavior, keyboard actions, screen-reader
labels, and status that is understandable without color.

Inspect every deterministic fixture at a desktop viewport and a narrow
viewport in light and dark themes. Record the browser, exact viewport, date,
and result. Check long command wrapping, long host and model names, output
gaps, reduced motion, and recovery after reload.

## Exact validation commands

Run from the repository root on the same checkout used for live evidence.
Format only changed Zig files. If the first query returns no files, omit the
`zig fmt` command instead of running it with an empty argument list.

```sh
git diff --name-only --diff-filter=ACMR HEAD -- '*.zig'
git diff --name-only --diff-filter=ACMR HEAD -- '*.zig' | xargs zig fmt --check
zig build
zig build test
scripts/integration-test.sh
npm --prefix frontend test
npm --prefix frontend run build
frontend/node_modules/.bin/tsc -p frontend/tsconfig.json --noEmit
git diff --check
```

The automated suite is necessary but not sufficient. Record these external
results on the same checkout:

- one real OpenAI Responses stream with a current model, native credential
  configuration, `store:false`, strict Structured Outputs, request IDs, one
  harmless approved container command, and a complete secret scan
- one separately pinned Ollama or vLLM Chat Completions adapter test
- verified process-group cancellation, including a child process
- restart recovery at every non-terminal turn state
- the complete deterministic preview matrix at desktop and narrow widths in
  both themes

Do not put an API key, prompt body, server context, or model response in the
evidence log. Record redacted request shape, provider and client request IDs,
terminal event type, proposal identity, command hash, execution identity, and
test result.

## Open release gates

Every gate remains open while Spec 11 is Planned:

- [ ] **Main-thread gate:** a slow 20-second context probe and a slow provider
  stream do not delay unrelated bridge calls. No AI handler waits on network
  work.
- [ ] **Native credential gate:** native secure entry, `App.start_fn`
  injection, status, use, replacement, deletion, overwrite, and shutdown pass
  without a key entering React or persistent app data.
- [ ] **Real OpenAI gate:** a current model completes one native Responses
  `store:false` stream with strict `text.format`, request IDs, a validated
  proposal, and no secret leak.
- [ ] **Compatibility gate:** one pinned Ollama or vLLM version passes the
  separate `openai_chat_completions` adapter. A failed or stale test blocks
  Ask.
- [ ] **Disclosure gate:** the user reviews the exact selected context and log
  bound. A log prompt-injection fixture cannot change policy, approve, or call
  SSH.
- [ ] **Proposal gate:** no runnable card exists before full stream and local
  validation. Refusal, incomplete output, schema failure, malformed known
  events, timeout, and multiple results fail closed.
- [ ] **Approval identity gate:** Run commits the exact durable revision for
  the visible server and connection. Edit, target change, provider change,
  expiry, hash mismatch, and a second click reject or deduplicate as specified.
- [ ] **Destructive gate:** the shared Zig and React fixture set agrees, edited
  commands are reclassified, and the backend requires the warning
  acknowledgement.
- [x] **Execution and audit gate:** one harmless approved container command
  uses `history_kind = "ai"`, streams through independent cursors, and
  finishes the same operation in AI history and audit. Generic SSH rows stay
  out.
- [x] **Cancellation gate:** provider cancel has honest semantics. SSH cancel
  stops and verifies the remote process group and child. An uncertain stop
  remains `cancel_requested|recovery_required`.
- [ ] **Recovery gate:** forced restart at every non-terminal state produces no
  duplicate provider POST and no duplicate SSH command. An unexpired proposal
  restores exactly.
- [ ] **Conversation gate:** local `store:false` continuation replays every
  required adapter item, including returned encrypted reasoning items,
  without a server Conversation, background mode, or `previous_response_id`.
  Clear Thread removes local conversation data.
- [ ] **Save-as-script gate:** the exact proposal opens as a reviewed script
  draft and the saved script runs through Spec 06.
- [ ] **UI gate:** all typed states pass desktop, narrow, keyboard, focus,
  screen-reader, light-theme, and dark-theme review with target and provider
  identity always visible.
- [ ] **Repository gate:** every validation command and external evidence item
  above passes on the same checkout.

Only after all gates close may the implementation change update Spec 11 and
`docs/specs/README.md` from Planned. Update this guide at the same time with
dated evidence. A partial backend, a polished mock UI, or a successful generic
`oars.ssh.exec` call does not justify Partial or Complete status.

## Non-goals

Keep this implementation out of:

- autonomous execution or approval by the model
- OpenAI built-in shell, computer, web, file, code-interpreter, or MCP tools
- native Anthropic, Gemini, or other provider protocols
- a cloud proxy, account brokerage, telemetry, or shared prompt service
- browser-side provider HTTP, permissive `connect-src https:`, or CORS-based
  provider support
- automatic retry after an ambiguous POST
- server-side OpenAI Conversations, `previous_response_id`, or background
  Responses jobs
- raw-log retention by default
- cross-server chat or fleet command execution
- changes to unrelated terminal, deployment, backup, or vault workflows

## Primary sources

### Repository and installed source

- Target product contract: `docs/specs/11-ai-terminal.md`.
- Current-state audit and architecture research:
  `docs/research/spec-11-ai-terminal-current-state.md`.
- Cross-cutting cursor, secret, approval, cancellation, and threading rules:
  `docs/specs/README.md:52-91`.
- UI rules: `docs/DESIGN.md:109-126` and
  `docs/DESIGN.md:169-203`.
- Current AI backend: `src/ai.zig`, AI registrations and handlers in
  `src/bridge.zig`, and `src/integration_ai.zig`.
- Current frontend: `frontend/src/AiTab.tsx`,
  `frontend/src/types.ts`, `frontend/src/bridge.ts`,
  `frontend/src/App.tsx`, `frontend/src/test/mock-bridge.ts`, and
  `frontend/index.html`.
- Runtime ownership: `src/main.zig:145-236` and
  `src/runner.zig:401-575`.
- Native credential and injection APIs: installed
  `@native-sdk/cli/src/runtime/system_services.zig:89-108`,
  `runtime/core.zig:754-769`, `runtime/api.zig:410-447`,
  `runtime/flow.zig:227-240`, and
  `platform/types.zig:239-241,2401-2403,2902-2914`.
- Installed Zig HTTP client:
  `/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/std/http/Client.zig`.

### External primary documentation

- [OpenAI API authentication](https://developers.openai.com/api/reference/overview)
  defines server-side key handling, request IDs, and compatibility policy.
- [OpenAI Responses create](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
  defines `stream`, `store`, output items, the
  `reasoning.encrypted_content` include value, tools, and response state.
- [OpenAI Chat Completions create](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
  defines the separate compatibility request and streaming contract.
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
  defines strict Responses `text.format` JSON Schema output.
- [OpenAI streaming responses](https://developers.openai.com/api/docs/guides/streaming-responses)
  defines typed Responses stream events.
- [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling)
  defines `call_id`, strict schemas, tool results, and
  `parallel_tool_calls:false` for later tool work.
- [OpenAI conversation state](https://developers.openai.com/api/docs/guides/conversation-state)
  defines local `store:false` continuation with all required response output
  items, including reasoning items.
- [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data)
  defines Responses application-state retention, Zero Data Retention, and
  background-mode limits.
- [OpenAI agent safety](https://developers.openai.com/api/docs/guides/agent-builder-safety)
  defines prompt-injection, structured-output, and approval guidance.
- [OpenAI safety best practices](https://developers.openai.com/api/docs/guides/safety-best-practices)
  defines adversarial testing, human review for code, and input/output bounds.
- [WHATWG server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
  defines UTF-8 SSE lines, comments, multiple data lines, and event
  termination.
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)
  and [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
  document explicit routes and compatibility limits. They require a tested
  adapter instead of a generic compatibility claim.
