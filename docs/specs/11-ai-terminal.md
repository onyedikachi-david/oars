# Spec 11 — AI Terminal

**Status:** Partial: native provider, durable turn/proposal, exact SSH execution, cancellation, and the React workflow are implemented; live-provider, real credential-store, forced-restart, and final accessibility evidence remain · **Depends on:** 02 (exec), 03 (context), 04 (log context), 06 (save as script), 15 (audit) · **Spec owner:** core + frontend

## 1. Overview

The user asks a question about one selected server. A native Zig provider
worker sends the selected context to the configured model and returns one
validated command proposal or one question. The user can edit and approve the
proposal. Oars runs only the exact server-bound command that the Zig core
stored for that approval. Each run has durable state, command history, and an
audit record.

Spec 19 extends this baseline with ordinary assistant messages and a
conversation-first UI. Its reviewed command card still projects this Spec 11
proposal lifecycle; it does not give the provider direct execution authority.

## 2. Goals and non-goals

**Goals**

- Provide a persistent conversation for each server, with explicit provider
  and context selection.
- Support the `openai_responses` adapter and the separate
  `openai_chat_completions` compatibility adapter.
- Keep provider HTTP, Transport Layer Security (TLS), stream parsing, and API
  key use in native Zig code.
- Return a strict command or question object. Do not extract a command from
  free text or incomplete streamed data.
- Freeze each command proposal in Zig before the UI can approve it. Bind the
  approval to the server, proposal revision, and command hash.
- Stream command output, support honest cancellation and restart recovery,
  save a reviewed command as a script, and write AI-specific history and
  audit records.

**Non-goals**

- The WebView does not call a provider and does not read an API key.
- The model cannot execute a command, call a local function, use Model Context
  Protocol (MCP), or use an OpenAI built-in tool in v1.
- Oars does not execute a proposal automatically, retry an ambiguous provider
  request automatically, or run a command after restart.
- Oars does not provide a cloud proxy or telemetry service.

## 3. User stories

- I ask why a selected server has little free disk space. I review one command
  and its explanation before I run it.
- I select a bounded log tail. Oars shows the exact fields that will leave my
  computer before it sends the request.
- I edit a proposal. Oars creates a new revision and checks the edited command
  again before it enables Run.
- I cancel a provider request or a remote command. Oars shows whether the stop
  is verified or still uncertain.
- I close and reopen Oars. My local conversation and an unexpired proposal
  return, but Oars does not repeat a provider request or a command.
- I open an approved command in the script editor and review it before I save
  it.

## 4. UI and interaction

### 4.1 Header and provider setup

- The header always shows the selected server, SSH user, provider, endpoint
  origin, model, and credential status. The AI panel must never select
  `servers[0]` as a fallback.
- Provider setup includes name, adapter, base URL, model, and adapter-specific
  compatibility fields. The user must run **Test provider** before Ask is
  enabled. The test warns that it can use provider quota.
- **Configure key** opens a native secure-entry sheet. React receives only
  `configured`, `missing`, `denied`, or `unavailable`. If native secure
  entry is unavailable, provider setup is unavailable. There is no WebView
  input fallback for the key.

### 4.2 Context disclosure

- Context controls cover operating-system data, monitor data, and one optional
  log tail. Log content is off by default.
- Before the first request, and after any selection change, a disclosure view
  shows each selected field, the log source, and the maximum bytes that Oars
  will send. The user can remove any optional field.
- Host names, process text, user text, and log text are untrusted data. Oars
  puts them in labeled user content. Oars never puts them in the developer
  instruction.

### 4.3 Turn and proposal

- The turn states are `queued`, `collecting_context`, `requesting`,
  `streaming`, `validating`, `awaiting_approval`, `approved`, `executing`,
  `summarizing`, `completed`, `failed`, `cancel_requested`, `canceled`,
  `interrupted`, and `recovery_required`.
- During a model stream, the UI shows progress. It does not show partial JSON
  as assistant text and does not show a Run button.
- A validated command card shows the exact server, command, explanation,
  `Destructive` and `Needs sudo` states, revision, and expiry.
  The actions are **Run**, **Edit**, **Cancel**, and **Open in script editor**.
- A question result shows the question and has no Run action. A refusal,
  incomplete response, schema error, or protocol error has no command card.
- An edit goes through Zig and creates a new revision. The old revision cannot
  run. Zig is authoritative for destructive detection. React can use the same
  fixture list only to give faster feedback.
- Destructive state is the logical OR of the model flag and the Zig heuristic.
  The card shows a clear warning. Run must send
  `destructive_warning_ack:true` for that revision.
- A command that needs an interactive sudo password is blocked. The UI tells
  the user to use the interactive terminal. Oars never asks the model or the
  AI panel for a sudo password.

### 4.4 Output, cancellation, and errors

- Command output uses the existing SSH cursor stream and shows output gaps,
  exit status, duration, and the final verified state.
- Cancel before approval expires the proposal. Provider Cancel stops local
  network work, but the UI states that the provider can already have received
  and billed the request.
- A remote command is `canceled` only after Oars signals its tracked remote
  process group and verifies termination. Otherwise the state remains
  `cancel_requested` or becomes `recovery_required`.
- The UI has explicit states for no server, disconnected server, no provider,
  untested provider, missing key, denied key access, context loading, stale or
  partial context, authentication failure, rate limit, timeout, invalid model
  output, connection loss, expired proposal, stale proposal, used proposal,
  dropped output, and restart recovery.
- Status uses text and an icon, not color alone. Controls remain keyboard
  reachable, and focus returns to the action that opened a sheet. Commands use
  monospace text. Normal interface text does not.

## 5. Bridge API

All timestamps are integer epoch milliseconds. Revisions and cursors are
integers. An `operation_id` is 1 to 64 ASCII letters, digits, dots, colons,
underscores, or hyphens. A caller reuses it only to retry the same mutation.
User-facing failures return `{ok:false, code, error}`. Stable codes include
`invalid_argument`, `not_found`, `conflict`, `stale_revision`,
`not_connected`, `credential_missing`, `provider_untested`, `busy`,
`limit_exceeded`, `provider_auth`, `provider_rate_limited`,
`provider_timeout`, `provider_protocol`, and `recovery_required`.

### 5.1 Provider and credential

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

The provider draft is `{id?, name, adapter, base_url, model,
instruction_role?, structured_output?}`. `ProviderPublic` adds `{revision,
tested_at_ms?, test_status}` and never contains a key. `adapter` is
`openai_responses` or `openai_chat_completions`. `test_status` is `untested`,
`passed`, `failed`, or `stale`. A route, model, adapter, compatibility-setting,
or credential change makes the test stale. The Keychain account is
`ai:<provider_id>`. Deleting provider metadata does not silently delete its
credential; the UI offers the separate credential delete action.

### 5.2 Context

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

`context.get` reads a cache only. It does not start SSH work. `refresh` queues
one complete operating-system, monitor, process, disk, and log-metadata probe
on the selected server session worker and returns without a network wait. It
does not depend on the separate Monitor-tab cache. The returned context does
not contain log bytes. `turn.start` reads only the selected bounded log tail.

### 5.3 Threads, turns, and proposals

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

oars.ai.proposal.edit {operation_id, proposal_id, expected_revision, command}
  -> {ok, proposal:Proposal}

oars.ai.proposal.run {
  operation_id, proposal_id, expected_revision,
  command_sha256, destructive_warning_ack
} -> {ok, execution_id, channel, state}

oars.ai.proposal.cancel {operation_id, proposal_id, expected_revision}
  -> {ok, state:"canceled"}
```

`thread.get` returns all turns when they fit the bridge response bound. For a
larger thread, it returns the largest latest-turn suffix that fits.
`turns_start` identifies the first returned turn and `turn_count` reports the
durable total. The command returns `limit_exceeded` when the latest turn alone
cannot fit.

The summary action is a new provider request. Before admission, the UI shows
the exact bounded command-output range that it will send. Save as script opens
the Spec 06 editor with the proposal command as a draft. The editor calls
`oars.scripts.save` only after the user reviews the script. An existing thread
remains bound to its server, provider adapter, and model. A mismatch requires a
new thread.

### 5.4 Versioned events

`EventPoll` is `{ok, stream_id, cursor, dropped, finished, state, events}`.
Each event is `{version:1, sequence, stream_id, type, payload}`. The
cursor is an absolute event sequence. Reads are non-destructive. `rewind:true`
starts at the first retained event. `dropped` reports the number of events that
the caller missed.

Provider-test events are `provider.test_started`, `provider.test_succeeded`,
`provider.test_failed`, and `provider.test_canceled`. Context-refresh events
are `context.refresh_started`, `context.ready`, `context.failed`, and
`context.canceled`.

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

Provider JSON and provider server-sent event (SSE) names do not cross the
bridge. The adapter converts them to these domain events. `proposal.ready` is
written only after the full response passes the local schema and domain checks
and the proposal is durable. Command bytes remain in `oars.ssh.poll`; Oars does
not copy them into the AI event journal.

## 6. Zig core design

### 6.1 Runtime and credential ownership

- The installed Native SDK exposes `App.start_fn(context, *Runtime)` and
  `Runtime.setCredential`, `Runtime.getCredential`, and
  `Runtime.deleteCredential`. Oars must set `App.start_fn` to install a narrow
  credential service in `bridge.Context`. The current bridge does not have
  this runtime pointer.
- The Native SDK does not state that credential methods are safe on any
  thread. The facade is runtime-thread-bound. A bridge admission handler
  validates the provider and operation, reads at most 4096 key bytes into a
  request-job buffer, queues the job, and returns. The worker overwrites the
  key buffer on every exit path.
- The raw `Runtime` pointer does not enter the AI worker. `App.stop_fn` stops
  new admission, cancels and joins provider workers, overwrites pending secret
  buffers, and then clears the facade.
- Native key configuration uses a native secure-entry service and calls the
  facade. This secure-entry service is an implementation prerequisite. The
  existing JSON credential bridge is not acceptable because its payload
  originates in the WebView.

### 6.2 Provider coordinator and transport

- A native coordinator owns bounded provider workers, HTTP clients, request
  cancellation, adapters, events, and the journal. The runtime main thread
  performs validation, short credential reads, queue operations, and snapshot
  reads only. It does not wait for SSH or provider network work.
- V1 permits two active provider requests in total and one active request per
  thread. An accepted request is journaled before the worker can send it.
- Provider URLs must parse as HTTPS. User-approved HTTP is permitted only for
  a loopback address. URLs with user information, a fragment, or query data
  are invalid. Path joining is deterministic. Authenticated POST requests do
  not follow redirects.
- The credential is bound to the reviewed normalized origin. Oars does not
  send it to a redirect target. Oars never logs authorization headers,
  prompts, context bodies, or response bodies.
- A provider POST is not retried after any request byte can have reached the
  provider. Retry is an explicit new operation and can use more quota.
- Oars sends a generated `X-Client-Request-Id` to OpenAI and records the
  returned `x-request-id` when available. Errors and audit data contain only
  redacted request metadata.

### 6.3 Provider adapters and model output

Each adapter owns request construction, status handling, incremental byte
parsing, final validation, and retry classification.

- `openai_responses` uses `POST /v1/responses` with `stream:true`,
  `store:false`, `background:false`, and strict `text.format` JSON Schema.
  It requests `reasoning.encrypted_content` in `include`. It does not use
  `previous_response_id` or a Conversation object. A later turn replays the
  locally retained output items that OpenAI requires, including the opaque
  encrypted reasoning item when OpenAI returns one.
- `openai_chat_completions` uses `POST /v1/chat/completions`. It is a separate
  compatibility adapter with separately tested SSE parsing, instruction role,
  and structured-output mode. It supports only `json_schema` or `json_object`.
  There is no prompt-only JSON fallback.
- Provider Test sends the exact selected route, model, instruction role, stream
  format, and schema mode. A models-list request is not capability proof. A
  failed or stale test blocks Ask.
- The Responses parser accepts typed lifecycle, output-item, text, refusal,
  incomplete, failure, and error events. It ignores unknown bounded event
  types because OpenAI can add event types. It rejects malformed known events,
  inconsistent item identity, duplicate terminal state, and a missing terminal
  state.
- The SSE parser supports UTF-8, CRLF and LF line endings, comments, multiple
  `data:` lines, and input split at any byte boundary.

The strict proposal object is:

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "kind": {"type": "string", "enum": ["command", "question"]},
    "command": {"type": ["string", "null"]},
    "question": {"type": ["string", "null"]},
    "explanation": {"type": "string"},
    "destructive": {"type": "boolean"},
    "needs_sudo": {"type": "boolean"}
  },
  "required": [
    "kind", "command", "question", "explanation", "destructive",
    "needs_sudo"
  ]
}
```

The local validator checks the discriminator, the one non-null payload, byte
limits, UTF-8, NUL bytes, and the complete command. It permits recognized
reasoning items but requires exactly one proposal-bearing message and one
structured result. A refusal, incomplete result, extra schema field, multiple
structured results, or validation error cannot create a proposal.

The OpenAI request does not declare tools. A returned function call, shell
call, computer call, MCP call, or other tool call is a protocol error. The
local Run action is not a provider tool. A future tool implementation needs a
separate specification with strict arguments, `call_id` correlation,
`parallel_tool_calls:false`, durable `awaiting_approval` state, and explicit
approval before local execution and before Oars sends a tool result.

### 6.4 Approval and execution

`Proposal` contains `{id, turn_id, revision, server_id, provider_id,
provider_revision, context_hash, command, command_sha256, explanation,
model_destructive, local_destructive, needs_sudo, created_at_ms,
expires_at_ms, state}`. A proposal expires after 10 minutes.

Run checks the proposal state, revision, hash, expiry, server identity,
connection identity, provider revision, and destructive acknowledgement under
one lock. It writes `ai.approved` before it admits the exact frozen command to
the tracked SSH exec path with `history_kind:"ai"` and the same operation ID.
A second Run returns the first admission result and does not start a second
channel. The public `oars.ssh.exec` command is not the AI approval boundary.

AI execution must start and track a remote process group. Cancel sends a
signal to that group and verifies termination. Channel close alone is not a
verified stop. Completion updates the same operation with exit status,
duration, and a bounded redacted output sample.

## 7. Data model and persistence

- `<data>/ai.json` stores provider metadata with stable IDs and integer
  revisions. It contains no key. Write a mode-0600 temporary file, sync it,
  and rename it atomically.
- `<data>/ai_journal.jsonl` stores versioned thread, turn, proposal, approval,
  execution, and recovery records. Append and sync each state transition.
  Compaction writes and syncs a mode-0600 temporary file before atomic rename.
- The journal stores user messages, validated assistant results, and the
  adapter-owned continuation items needed for `store:false` conversations.
  It keeps `reasoning.encrypted_content` opaque and never shows or interprets
  it. It does not store raw log context by default. It stores the log
  selection, byte count, and hash. Clear Thread removes local conversation
  data but does not erase audit or command history.
- The key stays in the operating-system credential store as
  `ai:<provider_id>`. A transient native request buffer contains it only while
  Oars builds and sends one request. The provider receives the key in its
  authorization header.
- On startup, `queued`, `collecting_context`, `requesting`, `streaming`, and
  `validating` become `interrupted`. They do not restart. An unexpired
  `awaiting_approval` proposal can return. `approved` without an execution
  admission becomes `recovery_required`. An `executing` turn reconciles with
  its tracked channel; an absent channel becomes `recovery_required`. Oars
  never repeats a provider POST or SSH command during recovery.

V1 bounds are:

- 16 providers, 100 threads, and 50 turns per thread.
- 16 KiB for one user message, 64 KiB for one command, 8 KiB for one
  explanation or question, and 64 KiB for one selected log tail.
- 128 KiB for a provider request body, 64 KiB for response headers, 256 KiB
  for one SSE event, 128 KiB for accumulated structured output, and 8 KiB for
  a retained provider error body before redaction.
- 1024 retained domain events or 1 MiB per turn, whichever is reached first.
  The cursor response reports dropped events.
- 512 KiB of adapter continuation items per thread. Compaction removes the
  oldest terminal turns first and never removes an active proposal or
  execution. If required continuation items still exceed this limit, Oars
  blocks another turn and asks the user to start a new thread. It does not
  silently remove protocol items.

## 8. Security and privacy

- A standard provider API key never enters React memory, browser storage,
  bridge JSON, frontend traces, configuration files, journals, audit records,
  history, or error text. Tests scan all of these paths. Native buffers are
  overwritten after use.
- Keep the packaged WebView Content Security Policy narrow. Provider CORS is
  not part of the request path because all provider HTTP is native.
- Static policy goes in the developer instruction. User text and server
  context remain labeled untrusted user data. Prompt injection in a log cannot
  change the local schema, create an approval, or call SSH.
- `store:false` prevents Responses application-state storage for the request.
  It does not promise that the provider keeps no abuse-monitoring data. The
  disclosure view links to the selected provider policy.
- A model result is untrusted input. Only the validated, durable proposal can
  reach the approval handler, and only the exact approved revision can reach
  the AI execution path.
- Deleting a thread, provider, or credential is explicit. No delete action
  silently removes a different class of data.

## 9. Performance and time limits

- A bridge handler must not wait for SSH or provider network input. Unrelated
  bridge calls must remain responsive during a 20-second context probe and a
  slow provider stream.
- Provider time limits are 10 seconds to connect, 30 seconds to the first
  response byte, 30 seconds of stream idle time, and 120 seconds total. The UI
  can cancel sooner.
- Context cache age is at most 5 seconds for a fresh result. A stale result is
  labeled and does not start a hidden refresh.
- Provider progress events are coalesced to at most 10 updates per second.
  Command output continues to use the Spec 02 stream bounds.

## 10. Edge cases

- A server, provider, or proposal revision changes while a card is open. Run
  rejects the stale card and requires a new proposal.
- The provider returns 401, 429, 5xx, invalid UTF-8, a redirect, an oversized
  event, a refusal, or an incomplete response. Oars returns the typed state and
  never creates a command from invalid data. It ignores an unknown bounded
  event and continues to require a valid known terminal event.
- The connection drops after request bytes are sent. Oars marks the turn
  interrupted and requires an explicit new request.
- A pipeline, heredoc, quote, or newline occurs in a command. Oars preserves
  the complete frozen string and uses the same checked shell-command transport
  as Spec 06. It does not split the string into a false argument vector.
- The user edits a safe proposal into a destructive command. Zig adds the
  warning to the new revision before Run can succeed.
- Oars restarts between approval and SSH admission. The turn becomes
  `recovery_required`; it does not execute on startup.

## 11. Testing

| Layer | Required proof |
|---|---|
| Zig unit | URL and redirect policy, request bounds, every SSE byte split, CRLF and LF, multi-line data, unknown and malformed events, adapter terminal states, strict schema, destructive fixtures, stale revisions, double Run, journal replay, truncated tail, compaction, and every restart state. |
| Native credential integration | Configure, replace, status, read, delete, denied and unavailable services, the 4096-byte bound, runtime-thread dispatch, worker-buffer overwrite, shutdown order, and no secret in frontend or persistent data. |
| Local provider integration | A deterministic native HTTP fixture checks authorization without printing it, fragments streams, delays data, returns 401, 429, and 500, attempts a redirect, drops a connection, and verifies cancel cleanup and no automatic retry. |
| SSH container integration | Ask fixture, validate, edit, approve, run the exact command, stream output, record AI history and audit, reject a second Run, switch servers, disconnect, hard-cancel a child process, restart during each state, and open a script draft. |
| React tests | Exhaustive reducer states, cursor gaps, stale poll responses, explicit server selection, context disclosure, no partial runnable card, edit revision, destructive acknowledgement, credential status only, focus return, keyboard use, and accessible status labels. |
| Live provider acceptance | One real OpenAI Responses turn uses `store:false`, strict Structured Outputs, typed streaming, request IDs, a harmless approved container command, and no secret in app data or traces. One pinned Ollama or vLLM version passes the explicit Chat Completions adapter separately. |
| Manual review | Desktop and narrow widths, light and dark themes, long host, model, explanation, and command values, every error class, dropped output, reduced motion, and restart recovery. |

## 12. Acceptance criteria

- [ ] A slow context refresh and provider stream do not delay unrelated bridge
  calls. No bridge handler waits on network work.
- [ ] Native secure entry, `App.start_fn` credential injection, request use,
  buffer overwrite, delete, and shutdown pass without a key entering React or
  persistent app data.
- [ ] A real OpenAI Responses request uses `store:false`, strict
  `text.format`, typed streaming, and request IDs, then produces one validated
  proposal.
- [ ] One pinned compatible provider passes the explicit
  `openai_chat_completions` adapter test. A failed or stale provider test
  blocks Ask.
- [ ] The user reviews the exact context fields and bounded log selection.
  Prompt injection fixtures cannot change policy or execute a command.
- [ ] No runnable card exists before complete stream validation. Refusal,
  incomplete output, schema failure, malformed known events, timeout, and
  multiple structured results fail closed.
- [ ] Run executes the exact frozen command for the visible server. Edit,
  server switch, provider change, expiry, hash mismatch, and a second click
  reject or deduplicate admission as specified.
- [ ] The Zig destructive fixture list and React mirror agree. An edited
  destructive command requires the warning acknowledgement.
- [x] One approved harmless command runs on the real SSH container, streams
  through cursor polling, records `history_kind:"ai"`, and completes the same
  operation in history and audit. Generic SSH rows do not appear as AI runs.
- [x] Provider cancel has an honest terminal state. SSH cancel stops and
  verifies the remote process group and its child process. An uncertain stop
  remains `cancel_requested` or `recovery_required`.
- [ ] Forced restart at every non-terminal state causes no duplicate provider
  POST and no duplicate SSH command. An unexpired proposal restores exactly.
- [ ] Local multi-turn continuation with `store:false` replays all required
  adapter items, including returned encrypted reasoning items. Clear Thread
  removes local conversation data.
- [ ] Save as script opens the exact proposal as a draft and the reviewed
  script runs through the Spec 06 contract.
- [ ] The full UI state set passes desktop, narrow, keyboard, focus,
  screen-reader, light-theme, and dark-theme review with the server and
  provider always visible.
- [ ] The same checkout passes:

  ```sh
  git diff --name-only --diff-filter=ACMR -- '*.zig' | xargs zig fmt --check
  zig build
  zig build test
  scripts/integration-test.sh
  npm --prefix frontend test
  npm --prefix frontend run build
  git diff --check
  ```

All boxes remain unchecked while this spec is Planned. A mock provider, a
direct `oars.ssh.exec` call, or a unit-only credential test is not end-to-end
release evidence.

## 13. Research and references

Research on 2026-08-31 corrected these parts of the previous draft:

- Provider requests moved from the WebView to native Zig because OpenAI says
  that standard API keys must not be exposed in browser or app client code.
- OpenAI uses the Responses API with strict structured text output. Chat
  Completions remains a separate compatibility adapter, not one generic
  protocol for all providers.
- The installed Native SDK has backend credential methods and an
  `App.start_fn` injection hook, but Oars does not wire that hook today. Native
  secure key entry is still a prerequisite.
- The Run button alone was not an approval boundary. The corrected contract
  uses a durable Zig proposal, revision, server identity, hash, and idempotent
  admission.
- Context refresh moved off the bridge thread. Threads, turns, proposals, and
  ambiguous recovery became durable.
- The previous checked approval and Keychain claims had no end-to-end proof.
  This version resets every acceptance box.

Repository and installed-source evidence:

- Spec status, cursor streams, secrets, cancellation, and threading:
  `docs/specs/README.md:1-10`, `docs/specs/README.md:52-91`.
- Current AI scaffold and gaps: `src/ai.zig:1-679`,
  `src/bridge.zig:12513-12730`, `src/integration_ai.zig:1-207`,
  `frontend/src/AiTab.tsx:1-130`, `frontend/src/types.ts:856-941`, and
  `frontend/index.html:5-8`.
- Native SDK credential service and injection hook:
  `@native-sdk/cli/src/runtime/system_services.zig:89-108`,
  `@native-sdk/cli/src/runtime/core.zig:754-769`,
  `@native-sdk/cli/src/runtime/api.zig:410-447`,
  `@native-sdk/cli/src/runtime/flow.zig:227-240`, and
  `@native-sdk/cli/src/platform/types.zig:239-241`,
  `@native-sdk/cli/src/platform/types.zig:2401-2403`,
  `@native-sdk/cli/src/platform/types.zig:2902-2914`. `build.zig:35` selects
  the installed package root.
- Current runtime ownership: `src/main.zig:167-204`,
  `src/main.zig:216-236`, and `src/runner.zig:470-521`.

External primary sources:

- [OpenAI API authentication](https://developers.openai.com/api/reference/overview)
  defines server-side key handling, request IDs, and compatibility policy.
- [OpenAI Responses create](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)
  defines `stream`, `store`, output items, the
  `reasoning.encrypted_content` include value, tools, and terminal response
  state.
- [OpenAI Chat Completions create](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
  defines the separate Chat Completions request and streaming contract.
- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
  defines strict Responses `text.format` JSON Schema output.
- [OpenAI streaming responses](https://developers.openai.com/api/docs/guides/streaming-responses)
  defines typed Responses stream events.
- [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling)
  defines `call_id`, strict tool schemas, tool outputs, and
  `parallel_tool_calls:false` for future tool work.
- [OpenAI conversation state](https://developers.openai.com/api/docs/guides/conversation-state)
  defines local `store:false` continuation with all required output items.
- [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data)
  defines Responses retention, Zero Data Retention, and background-mode limits.
- [OpenAI agent safety](https://developers.openai.com/api/docs/guides/agent-builder-safety)
  defines prompt-injection, structured-output, and approval guidance.
- [WHATWG server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
  defines UTF-8 SSE line and multi-line data parsing.
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)
  and [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)
  document explicit routes and compatibility limits. They support a separate,
  tested compatibility adapter instead of a generic capability claim.
