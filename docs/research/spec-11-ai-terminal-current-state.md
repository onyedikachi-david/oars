# Spec 11 AI Terminal: current state and implementation research

**Research date:** 2026-08-31

**Checkout:** `48091a9aba80a0a0cd6d3fdb151d57090093fe03`, with the full current working tree inspected

**Scope:** Spec 11 only. This file records evidence and proposes a corrected implementation contract. It does not change `docs/NEXT-SPEC.md` or Spec 10.

## Finding

Spec 11 is not implemented. The current checkout has provider metadata storage, a server-context probe, and a generic SSH audit view. It does not have a provider request, a chat turn, typed provider streaming, a validated command proposal, an approval-bound execution path, AI-specific history, cancellation, recovery, or save-as-script UI.

The present browser-direct design must change before implementation. OpenAI states that an API key must not be exposed in client-side code such as a browser or app. The packaged WebView also blocks provider HTTPS requests with its current Content Security Policy. Oars must put provider HTTP, streaming, and transient key use in a native Zig worker. This worker must receive the key through a narrow native credential service. It must not receive a key through React state or a normal bridge payload.

The next implementation must also fix one P0 blocker. `oars.ai.context` calls an SSH operation that can wait for 20 seconds from the bridge handler. This breaks the repository rule that the runtime main thread never blocks on network work.

## Corrections required in Spec 11

| Current contract | Evidence | Required correction |
|---|---|---|
| The WebView calls the provider directly. | Spec 11 states this at `docs/specs/11-ai-terminal.md:55-63`. The packaged CSP permits only the app origin and loopback WebSocket connections at `frontend/index.html:5-8`. OpenAI says keys must not be exposed in client-side browser or app code. | A native Zig worker owns HTTP, TLS, SSE parsing, provider state, and transient key use. Keep the WebView CSP narrow. |
| Chat Completions is the one generic provider protocol. | The current enum has only `openai_compatible` and `custom`, and its capabilities do not define a route or event grammar at `src/ai.zig:40-69`. | Add explicit protocol adapters. Use `openai_responses` for OpenAI. Keep `openai_chat_completions` as an explicit compatibility adapter. Native Anthropic and Gemini protocols remain future adapters. |
| The Run button is the security boundary. | `oars.ssh.exec` accepts any command with no approval token at `src/bridge.zig:655-687`. The current AI integration test calls it directly at `src/integration_ai.zig:165-203`. | The Zig core freezes the displayed proposal. Run commits that exact proposal by ID, revision, server ID, and command hash. A stale, edited, or server-switched proposal fails closed. |
| AI history is an audit-filtered list of AI runs. | `oars.ai.history` returns every `ssh.exec` audit entry for a server at `src/bridge.zig:12699-12729`. The generic exec path has no AI provenance at `src/bridge.zig:666-684`. | AI execution uses `history_kind = "ai"` and one stable `operation_id`. AI history filters that identity and carries proposal, approval, channel, exit, and recovery state. |
| Threads are ephemeral. | The current data model says this at `docs/specs/11-ai-terminal.md:97-101`. The registry contains only provider storage and a context cache at `src/ai.zig:440-457`. | Persist bounded local thread and turn state. A restart must restore proposals and must not repeat an ambiguous provider request or command. |
| Context is a light bridge call. | `aiProbeOrCache` calls `manager.execWait` with a 20-second timeout at `src/bridge.zig:12520-12575`. The cross-spec rule forbids main-thread network waits at `docs/specs/README.md:90-91`. | Make context refresh worker-owned. A bridge handler returns cached data or an operation ID immediately. Poll uses the standard non-destructive cursor contract. |
| The two checked acceptance claims prove the approval and key paths. | Spec 11 checks them at `docs/specs/11-ai-terminal.md:148-156`, but no AI Run handler or Keychain use exists in `AiTab`. | Reopen both claims. Require a real approval-bound run and a real native credential path as release evidence. |

## Current checkout

### Zig core

The useful base is small but real:

- `src/ai.zig:23-36` defines bounded provider, cache, and history limits.
- `src/ai.zig:104-137` accepts HTTPS endpoints and loopback HTTP endpoints.
- `src/ai.zig:139-248` loads provider metadata, quarantines corrupt JSON, and stores no API key.
- `src/ai.zig:265-369` builds and parses one shell-quoted OS, host, and log-mtime probe.
- `src/ai.zig:372-438` keeps a five-second, 16-server context cache.
- `src/bridge.zig:12600-12647` combines that probe with the monitor snapshot.
- `src/bridge.zig:12650-12697` gets and sets provider metadata and audits provider changes.
- `src/bridge.zig:12699-12729` reads generic SSH audit rows.

These parts are not an AI turn coordinator. The dispatcher exposes only `oars.ai.context`, `oars.ai.provider.get`, `oars.ai.provider.set`, and `oars.ai.history` at `src/bridge.zig:177-180`. There is no start, poll, cancel, proposal, approval, execution, or recovery handler.

The provider store also needs hardening before it becomes a coordinator store. `saveLocked` opens and truncates the final file, then changes its mode and writes it at `src/ai.zig:234-247`. It does not write a mode-0600 temporary file and atomically rename it. A crash can leave a partial final file. The next format also needs a stable provider ID and integer revision. A Keychain account must use `ai:<provider_id>`, not a mutable URL.

The URL check is a string-prefix check, not a full URI policy. For HTTPS it accepts all text after `https://` at `src/ai.zig:107-126`. The native transport must parse the URI, reject user information, fragments, and unexpected query data, define path joining, disable redirects by default, and bind the credential to the reviewed origin. Loopback HTTP must remain an explicit user choice. A resolved redirect must never receive the key or server context.

### Native credential seam

The installed Native SDK has a backend-callable credential API:

- `@native-sdk/cli/src/runtime/system_services.zig:89-108` implements `Runtime.setCredential`, `Runtime.getCredential`, and `Runtime.deleteCredential` over platform services.
- `@native-sdk/cli/src/runtime/core.zig:754-769` exports those methods on `Runtime`.
- `@native-sdk/cli/src/runtime/api.zig:410-447` defines `App.start_fn(context, *Runtime)`. The runtime calls it during `app_start` at `@native-sdk/cli/src/runtime/flow.zig:227-240`.
- `@native-sdk/cli/src/platform/types.zig:2401-2403` defines the platform function pointers, and `@native-sdk/cli/src/platform/types.zig:2902-2914` calls them.
- The API allows a credential secret of at most 4096 bytes at `@native-sdk/cli/src/platform/types.zig:239-241`.

Oars cannot call this API from its AI registry today. `App` creates `bridge.Context` before the runner starts at `src/main.zig:167-184`. `App.app()` sets `source_fn` but no `start_fn` at `src/main.zig:198-204`. `runner.runWithOptions` then creates and owns `native_sdk.Runtime` internally at `src/runner.zig:470-521`. No runtime or credential facade enters `bridge.Context`.

The installed SDK does not document the credential methods as safe to call from any thread. It marks other methods as any-thread methods when that property exists, but the credential function pointers have no such contract. Spec 11 must use `App.start_fn` to install a narrow credential facade in `bridge.Context`, then clear that facade in `stop_fn` before the runtime stops. The facade remains bound to the runtime thread. A bridge admission handler reads at most 4096 key bytes into a request-job buffer, queues the job, and returns. The native HTTP worker uses that buffer for one request and overwrites it on every exit path.

Do not pass the raw `Runtime` pointer to the AI worker. The API key still leaves the credential store to form the Authorization header, so the UI must not claim otherwise. If `App.start_fn` cannot meet the platform thread contract, the alternative is an Oars-owned platform credential adapter with the same behavior and tests. That alternative needs a separate design review; it is not present today.

Secure key entry is a separate prerequisite. The current Native SDK bridge can set a credential, but its JSON payload originates in the WebView. Spec 11 needs a native secure-entry sheet or an Oars-owned native credential prompt. React receives only `configured`, `missing`, or `unavailable`. It never receives the key value.

### React frontend

`AiTab` is a context and raw-config placeholder:

- It uses `any` for context, provider, and history at `frontend/src/AiTab.tsx:7-12`, although typed contracts exist at `frontend/src/types.ts:856-941`.
- It expects `entries` or `history` at `frontend/src/AiTab.tsx:25-29`, but the backend and the type return `runs`. The current history view is therefore empty.
- It labels raw context as sent to the model before a provider request or disclosure flow exists at `frontend/src/AiTab.tsx:58-82`.
- Its provider input suggests `{"type":"openai","api_key":"..."}` at `frontend/src/AiTab.tsx:84-106`. That shape does not match `AiProviderInput`, and it puts the key in WebView state.
- It has no prompt input, stream, structured parser, proposal card, Run, Edit, Cancel, command output, retry, or save-as-script flow.
- The app silently chooses `servers[0]` for AI at `frontend/src/App.tsx:1291-1295`. A command product must use an explicit active server and must never fall back to the first server.
- The shared mock returns stale AI shapes at `frontend/src/test/mock-bridge.ts:859-863`. No focused `AiTab` test exists.

The `updated_at_ns` field is also typed as a JavaScript `number` at `frontend/src/types.ts:868-874`. An epoch nanosecond integer is larger than the exact integer range of JavaScript. Use an integer millisecond timestamp or a decimal string on the wire. Use a separate integer `revision` for compare-and-commit checks.

### Current tests and what they prove

`src/integration_ai.zig:84-207` is one environment-gated SSH container test. It proves provider metadata round-trip, context collection, generic `oars.ssh.exec`, a marker file, and a generic audit row. It does not call an AI provider. It does not use a Keychain. It does not validate a stream or proposal. It does not prove a Run approval, edited-command identity, destructive handling, cancel, restart recovery, AI-specific history, or save-as-script.

The present unit tests in `src/ai.zig:464-679` cover provider validation, store round-trip, corrupt-file quarantine, probe parsing, and the context cache. They do not cover HTTP, TLS, redirects, credentials, SSE, Responses events, Chat Completions chunks, proposal schemas, approval, cancellation, or recovery.

## Target workflow

The v1 workflow must use these steps:

1. **Select the target.** The user selects one connected server and one configured provider. Oars shows the exact server name, host, user, provider, endpoint origin, model, and key status.
2. **Select context.** Oars shows the context fields before transmission. OS and resource summaries can be selected independently. Log text is off by default. The user selects a log and a bounded tail before Oars reads or sends it.
3. **Create a durable turn.** Zig writes a turn with `queued` state, a unique operation ID, server ID, provider ID and revision, context-selection hash, and user message. This write happens before the provider request.
4. **Resolve the key in native code.** The native credential facade reads `ai:<provider_id>`. The key never enters a React value, bridge JSON request, trace, error, or persisted file.
5. **Send through the provider worker.** The worker validates the effective endpoint again, sends the request, records a client request ID, and parses the response stream. The bridge thread remains free.
6. **Validate one complete proposal.** The OpenAI adapter uses Responses Structured Outputs. It buffers structured output until the final text item is complete. It parses and validates one object. It does not render a runnable card from a token delta.
7. **Freeze the preview.** Zig stores the command, explanation, model flags, local destructive flags, target, and revision. The UI renders only this backend-owned proposal.
8. **Edit through Zig.** An edit creates a new proposal revision. Zig re-runs the destructive heuristic and returns the new frozen preview. The old revision cannot run.
9. **Approve and execute.** Run sends only the proposal ID, expected revision, command hash, and destructive-warning acknowledgement. Zig records `ai.approved`, starts the exact frozen command with `history_kind = "ai"`, and returns the tracked SSH channel.
10. **Stream and finish.** Command bytes use the existing `oars.ssh.poll` cursor protocol. Exit status updates the same operation. A post-run summary is a new provider request only after the user sees which bounded output will be sent.
11. **Save as a script.** Save opens the existing script editor with the exact command as a draft. The user reviews the name, variables, and destructive tag before `oars.scripts.save` runs.

The model is a proposal source. It is not an execution authority. A model response, tool call, stream event, or restored journal entry can never call SSH directly.

## Provider architecture

### Native worker boundary

Create one provider coordinator that owns bounded worker threads, HTTP clients, request cancellation, adapter parsing, and the turn journal. The runtime main thread performs only validation, admission, snapshot reads, and short queue operations. The coordinator should allow at most two active provider requests in v1 and at most one active request per thread. These are proposed bounds and must have load tests.

Zig 0.16 includes `std.http.Client` TLS and streaming request support in the installed standard library. The implementation still needs a focused transport spike. It must prove CA loading, proxy policy, connect and read deadlines, cancellation, chunked bodies, SSE line splitting, and cross-platform packaging before the worker design is accepted.

Use these transport rules:

- Require HTTPS. Allow plain HTTP only for an explicitly approved loopback endpoint.
- Parse and normalize the URI. Do not accept URL user information. Do not log Authorization headers.
- Disable automatic redirects for authenticated provider POST requests. Return a reviewed-origin error instead.
- Bound request JSON, response headers, each SSE event, accumulated structured output, retained domain events, and error bodies.
- Use a connect deadline, a first-response deadline, an idle-stream deadline, and a total deadline. A user cancel closes the request.
- Do not retry a POST automatically after any request body byte can have reached the provider. An explicit Retry creates a new operation and states that it can consume more quota.
- Record `x-request-id` and a generated `X-Client-Request-Id` when the provider supports them. Store no key, prompt, context, or response body in diagnostic logs.

### Adapter contract

Do not use a boolean capability bag as a protocol definition. Each adapter must own these operations:

```text
buildRequest(turn, context, local_history) -> headers + body
acceptStatus(status, headers) -> typed provider error or stream
feedBytes(bytes) -> zero or more provider events
finish() -> one terminal result or a protocol error
classifyRetry(error, bytes_sent, response_started) -> never | explicit_only
```

Use these v1 adapters:

| Adapter | Route and format | Required behavior |
|---|---|---|
| `openai_responses` | `POST /v1/responses`; Responses typed SSE | Send `store:false`, `background:false`, `stream:true`, and strict `text.format` JSON Schema. Do not assume `output[0]` is assistant text. |
| `openai_chat_completions` | `POST /v1/chat/completions`; Chat Completions chunks | Use only after a provider test proves the selected instruction role, streaming grammar, and JSON or JSON-Schema mode. Parse its chunk grammar separately. |

Ollama states that it supports only parts of the OpenAI API and that its Responses state support differs. vLLM also lists supported routes and exceptions. A provider name or a successful `/models` call is not capability proof. The Test provider action must run the exact selected route and schema after a user click. It must warn that the test can consume quota. Persist the tested adapter version, model, normalized origin, result, and timestamp. Do not persist a key.

### OpenAI Responses request

For the OpenAI adapter, use one strict Structured Output object. Do not put the schema in prompt prose. A compatible shape is:

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "kind": { "type": "string", "enum": ["command", "question"] },
    "command": { "type": ["string", "null"] },
    "question": { "type": ["string", "null"] },
    "explanation": { "type": "string" },
    "destructive": { "type": "boolean" },
    "needs_sudo": { "type": "boolean" }
  },
  "required": ["kind", "command", "question", "explanation", "destructive", "needs_sudo"]
}
```

The local validator enforces the discriminator, one non-null payload, length limits, UTF-8, no NUL, and one command only. A `question` result never has a Run action. A refusal, incomplete response, multiple proposal-bearing messages, multiple structured results, or schema failure never creates a command card. Recognized reasoning items may still be part of a valid Responses result and local conversation state.

Keep static policy in the developer instruction. Put the user question and all host, process, monitor, and log data in user content with explicit data labels. Do not interpolate untrusted context into a developer message. The user-visible disclosure must show the exact selected fields and byte limits.

Send `store:false` on every OpenAI request and request
`reasoning.encrypted_content` in `include`. Do not use a server-side
Conversation object or background mode in v1. For multi-turn state, keep local
history and append every required Responses output item, including the opaque
encrypted reasoning item when the API returns one. Re-send the static
instruction on each turn. The UI must still state that the provider can keep
abuse-monitoring data under its own policy. `store:false` does not mean that no
provider retention exists.

### Function calling and future tools

The v1 command proposal uses structured text. It does not expose a shell function to the model. Local Run is an Oars approval action after the model request has ended.

If a later version adds function tools, the provider adapter must follow the full Responses tool loop:

- A `function_call` has a `call_id`, name, and JSON-encoded arguments.
- Streamed arguments remain non-runnable until their final event and local schema validation.
- Set `strict:true`, `additionalProperties:false`, and make every property required. Use nullable types for optional values.
- Set `parallel_tool_calls:false` for a single-proposal workflow.
- Persist a tool call as `awaiting_approval`. Do not call the function from the parser.
- After explicit approval and local execution, submit a `function_call_output` with the matching `call_id` only if the user approved sending the result.
- Never expose OpenAI built-in shell, computer, MCP, web-search, file-search, or code-interpreter tools in Spec 11 v1.

## Typed events and bridge contract

Raw provider JSON must stop at the adapter. React receives a versioned domain union. Use the repository cursor rule at `docs/specs/README.md:57-60`: each consumer sends an absolute cursor, reads are non-destructive, and `dropped` reports an overrun.

Proposed commands:

```text
oars.ai.provider.get {}
oars.ai.provider.set {provider, expected_revision?}
oars.ai.provider.test {operation_id, provider_id, expected_revision}
oars.ai.provider.testPoll {operation_id, cursor, rewind?}
oars.ai.provider.testCancel {operation_id}

oars.ai.credential.configure {provider_id}       # opens native secure entry
oars.ai.credential.status {provider_id}          # returns status only
oars.ai.credential.delete {provider_id}

oars.ai.context.get {server_id}                  # cached snapshot or loading state
oars.ai.context.refresh {operation_id, server_id}
oars.ai.context.poll {operation_id, cursor, rewind?}
oars.ai.context.cancel {operation_id}

oars.ai.turn.start {operation_id, thread_id?, server_id, provider_id,
                    expected_provider_revision, message, context_selection}
oars.ai.turn.poll {turn_id, cursor, rewind?}
oars.ai.turn.cancel {turn_id}

oars.ai.proposal.update {proposal_id, expected_revision, command}
oars.ai.proposal.run {operation_id, proposal_id, expected_revision,
                      command_sha256, destructive_warning_ack}
oars.ai.proposal.cancel {proposal_id, expected_revision}
oars.ai.thread.list {server_id?, limit}
oars.ai.thread.get {thread_id}
oars.ai.thread.delete {thread_id, expected_revision}
```

Proposed turn events:

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

Each event carries `version`, `sequence`, `turn_id`, and a typed payload. `turn.poll` returns `{ok, turn_id, cursor, dropped, finished, state, events}`. Token deltas for the structured JSON are counted as provider progress but are not rendered as assistant prose. `proposal.ready` is emitted only after the complete response passes local validation and is durable.

The OpenAI adapter must recognize response lifecycle events, output item events, text delta and done events, refusal events, incomplete and failed responses, and `error`. It must ignore unknown event types within size bounds because OpenAI can add new stream event types as a backwards-compatible change. It must fail on a malformed known event, an oversized event, missing terminal state, or inconsistent item identity. The SSE parser must support UTF-8, CRLF and LF, input split at any byte, comments, and multiple `data:` lines as defined by the HTML standard.

Command output continues to use the existing SSH channel and `oars.ssh.poll`. Do not copy the same byte stream into the AI event journal.

## Approval and execution boundary

The backend must own the prepare-to-commit identity. This follows the frozen preview pattern in Spec 06, where commit executes the prepared command verbatim at `docs/specs/06-scripts.md:98-113`.

A proposal record contains:

```text
proposal_id, turn_id, revision, server_id, provider_id, provider_revision,
context_hash, original_command, displayed_command, command_sha256,
model_destructive, local_destructive, needs_sudo, created_at, expires_at, state
```

Run checks all of these values under one lock before it records approval. A changed server, disconnected session, provider edit, proposal edit, expired proposal, used proposal, or command-hash mismatch rejects the run. Destructive state is the logical OR of the model flag and the backend heuristic. React may run the same heuristic for immediate feedback, but Zig is authoritative. Keep one shared fixture file so the two implementations cannot drift.

For a destructive proposal, the UI shows an explicit warning and Run sends `destructive_warning_ack:true`. For an ordinary proposal it sends `false`. A command that needs an interactive sudo password is blocked from exec and must move to the interactive terminal. Oars never puts a sudo password in the command or provider context.

The AI handler starts a tracked exec with `kind = "ai"` and the same operation ID. It writes one `ai.approved` audit entry before launch. History completion updates the same operation with exit, duration, and the bounded redacted output snippet. A double Run returns the existing admission result and never starts a second channel.

Cancellation has three meanings:

- Before approval, Cancel expires the proposal. No remote command exists.
- During a provider request, Cancel closes the HTTP stream and records `canceled` or `cancel_requested` if completion is uncertain. Oars does not retry automatically.
- During SSH execution, closing a channel is not proof that the remote process stopped. A completed Spec 11 cancel must start a remote process group, signal it, and verify termination. Until that exists, the state must remain `cancel requested`, as required by `docs/specs/README.md:78-81`.

## Persistence and recovery

Use a versioned, bounded local journal for threads, turns, proposals, and executions. Use append plus `fsync` for state changes and an atomic mode-0600 compaction file. Keep provider metadata in an atomic mode-0600 config file. No file contains an API key.

Recommended turn states are:

```text
queued -> collecting_context -> requesting -> streaming -> validating
       -> awaiting_approval -> approved -> executing -> summarizing -> completed
       -> failed | canceled | interrupted | recovery_required
```

Persist user messages and validated assistant messages so a local thread survives restart. Persist the provider-neutral output items that the active adapter needs for a stateless next turn. Do not persist raw log context by default. Persist its selection, byte count, and hash. If a user enables raw-context retention, show that choice and provide per-thread Clear.

On startup:

- `queued` and `collecting_context` turns can become `interrupted`; they do not start automatically.
- `requesting`, `streaming`, and `validating` become `interrupted`. Retry is an explicit new request because the provider can have received and billed the first request.
- `awaiting_approval` can restore the exact unexpired proposal.
- `approved` without an execution admission becomes `recovery_required`; it does not execute automatically.
- `executing` reconciles with the tracked SSH channel. If the channel is absent, mark `recovery_required`. Never run the command again.
- `summarizing` becomes `interrupted`; the command result remains final and a summary retry is optional.
- Terminal states remain terminal and idempotent.

Bound retained state. A proposed v1 bound is 100 threads, 50 turns per thread, 512 KiB of retained provider items per thread, and the existing history and audit bounds. Tests must prove compaction, overflow reporting, and recovery from a truncated last journal record. The final spec can change these numbers, but it must state them.

## Required UI states

The UI needs an explicit state for each action and failure:

- No server, server disconnected, and explicit server picker.
- No provider, provider not tested, missing key, credential service unavailable, and key access denied.
- Context loading, cached, stale, partial, failed, selected, and disclosure review.
- Provider test idle, quota warning, running, success, auth failure, rate limit, schema mismatch, and cancel.
- Turn queued, collecting context, sending, streaming, validating, question, refusal, incomplete, retryable failure, non-retryable failure, cancel requested, and canceled.
- Proposal ready, edited, stale, expired, destructive, needs sudo, approving, executing, and already used.
- Command output running, dropped bytes, cancel requested, exit success, exit failure, connection lost, and recovery required.
- Summary disclosure, summary running, summary failure, and summary skipped.
- Save-as-script review, saved, and save failure.

The active server, endpoint origin, and model stay visible above the composer and on every proposal. Do not use `servers[0]`. Run and Cancel remain keyboard reachable. Status uses text and an icon, not color alone, as required by `docs/DESIGN.md:175-203`. The command is monospace; normal UI text is not, per `docs/DESIGN.md:109-126`.

## Test matrix

| Layer | Required proof |
|---|---|
| Zig unit: URL and transport policy | Valid HTTPS, approved loopback HTTP, IPv6 loopback, user information, fragments, query data, path joining, redirect rejection, DNS and timeout classes, response-size bounds, and error-body redaction. |
| Zig unit: SSE | Every byte split, CRLF and LF, comments, multiple data lines, unknown event, malformed known event, duplicate terminal, missing terminal, invalid UTF-8, oversized line, oversized event, and cancel during a partial event. |
| Zig unit: adapters | Recorded official Responses fixtures for success, question, refusal, incomplete, failed, and error; recorded Chat Completions fixtures for the declared compatibility modes. |
| Zig unit: proposal | Strict-schema success and failure, discriminator rules, NUL and length limits, destructive fixtures, model/local flag merge, edit re-flag, stale revision, wrong server, wrong hash, expiry, and double Run. |
| Zig unit: persistence | Write-ahead admission, atomic provider save, journal replay, truncated tail, compaction crash, bounds, idempotent operation IDs, and each restart state. |
| Native credential integration | Configure, status, read, delete, denied access, missing service, platform unavailable, 4096-byte bound, correct-thread dispatch, transient buffer overwrite, and no secret in bridge traces or files. |
| Local provider integration | A deterministic local HTTP fixture checks Authorization without printing it, fragments SSE, delays reads, returns 401/429/500, attempts redirects, drops the connection, and proves cancellation cleanup. |
| SSH container integration | Ask fixture -> validated proposal -> approval -> exact command -> streamed output -> exit -> AI history and audit. Add edit-before-run, destructive warning, double Run, server switch, disconnect, hard cancel with a child process, restart during execution, and save-as-script. |
| React unit and integration | Exhaustive reducer, stale poll response, cursor gaps, explicit server selection, context disclosure, no partial runnable card, edit revision, destructive acknowledgement, retry copy, focus return, keyboard operation, screen-reader labels, and stale mock detection against the real wire types. |
| Live provider acceptance | One real OpenAI Responses stream with `store:false`, strict Structured Outputs, request IDs, a harmless approved container command, and no secret in app data or trace output. Test one pinned Ollama or vLLM compatibility adapter separately. |
| Manual UI review | Desktop and narrow widths, light and dark themes, long command wrapping, long host and model names, dropped output, every error class, restart recovery, and reduced motion. |

Do not treat a mock provider, a direct `oars.ssh.exec` call, or a unit-only Keychain test as end-to-end acceptance evidence.

## Release acceptance gates

Spec 11 can change from Planned only after all gates have dated evidence:

1. **P0 main-thread gate:** context refresh and provider work run off the runtime main thread. A slow 20-second SSH probe and a slow provider stream do not delay unrelated bridge calls.
2. **Native credential gate:** a user configures, reads, replaces, and deletes a provider key through the native path. The key is absent from WebView state, bridge JSON, call inspectors, config, journals, audit, history, errors, and logs. A memory-instrumented test proves that the request buffer is overwritten.
3. **Real OpenAI gate:** a current OpenAI model completes a Responses `store:false` streaming turn with strict Structured Outputs. Evidence includes the provider and client request IDs, redacted request shape, terminal event, and validated proposal.
4. **Compatibility gate:** one pinned Ollama or vLLM version passes its explicit adapter test. A failed capability test blocks Ask and explains the mismatch.
5. **Disclosure gate:** the user reviews the exact context fields and bounded log selection before the first request. A log prompt-injection fixture cannot alter the developer policy or execute a command.
6. **Proposal gate:** no runnable card exists before full stream completion and local validation. Refusal, incomplete output, invalid JSON, extra schema fields, multiple structured results, malformed known events, and timeout all fail closed. Bounded unknown event types remain forward-compatible and cannot create a proposal.
7. **Approval identity gate:** Run executes the exact backend-frozen command for the visible server. Edit, server switch, provider revision, expiry, and a second click invalidate or deduplicate admission as specified.
8. **Destructive gate:** the full fixture list and adversarial variants pass in Zig and React. An edited safe command that becomes destructive gains the warning before Run. The backend requires the warning acknowledgement.
9. **Execution and audit gate:** one approved harmless command runs on the real SSH container, streams with cursor polling, records kind `ai`, and finishes the same operation with exit and redacted output. A non-AI `ssh.exec` row does not appear as an AI run.
10. **Cancellation gate:** provider cancel stops local network work with an honest terminal state. SSH cancel kills and verifies the tracked remote process group, including a child process. If verification fails, the UI remains `cancel requested` or `recovery required`.
11. **Recovery gate:** forced restart tests at every non-terminal state produce no duplicate provider POST and no duplicate SSH command. An awaiting proposal restores exactly; an ambiguous request or execution requires user review.
12. **Conversation gate:** local `store:false` continuation replays every provider item required by the adapter. It does not use `previous_response_id`, Conversations, or background mode. Clear removes the local thread data.
13. **Save-as-script gate:** the approved or edited command opens a script draft, the user reviews it, and the saved script runs through the existing script contract.
14. **UI gate:** the complete state matrix passes desktop and narrow manual review, light and dark themes, keyboard use, focus return, and screen-reader checks. The target server and provider stay visible.
15. **Repository gate:** Zig format, Zig tests, frontend typecheck and tests, integration tests, `git diff --check`, and the repository release commands pass on the same checkout as the live evidence.

## Implementation sequence

1. **Correct the contract and types.** Update Spec 11 after review of this research. Define provider IDs and revisions, the adapter enum, domain events, the strict proposal schema, operation states, error codes, and generated TypeScript wire types.
2. **Remove the P0 context block.** Move context probes to the SSH worker operation queue. Make the bridge return cached data or an operation ID immediately. Add responsiveness and cancel tests.
3. **Create the native credential seam.** Set `App.start_fn` and `stop_fn` so `bridge.Context` receives a narrow, runtime-thread-bound facade for the installed credential service. Add native secure entry, status-only React APIs, transient job buffers, explicit overwrite, and secret-leak tests. Use an Oars-owned platform adapter only after a separate design review.
4. **Build the native provider worker.** Prove native TLS, CA loading, proxy policy, deadlines, cancellation, redirect rejection, bounded SSE, and request IDs with a local fixture.
5. **Implement adapters.** Land OpenAI Responses first with `store:false` and strict `text.format`. Add the separate Chat Completions compatibility adapter and an explicit provider test.
6. **Add the durable turn coordinator.** Land the journal, state machine, typed cursor events, restart reconciliation, and bounded local conversation items before the UI can call Ask.
7. **Add frozen proposals and execution admission.** Put destructive checks in Zig, add edit revisions and hashes, bind target identity, call tracked exec with kind `ai`, and make Run idempotent.
8. **Build the React state machine and UI.** Replace `any`, stale mocks, raw JSON config, and `servers[0]`. Add disclosure, provider setup, typed turn states, proposal cards, output, retry, cancel, and accessible focus behavior.
9. **Wire post-run summary and save-as-script.** Both are explicit follow-up actions. A summary has a second output-disclosure gate. Save opens the existing script editor.
10. **Collect release evidence.** Run the full automated matrix, one real OpenAI Responses turn, one compatible local-provider turn, real SSH execution and hard cancel, restart recovery, and manual UI review. Only then update acceptance boxes and status.

## Primary sources

### Repository and installed source

- Spec status and cross-cutting streams, secrets, approvals, cancellation, research, and threading: `docs/specs/README.md:1-10`, `docs/specs/README.md:52-91`.
- Current Spec 11 target and checked claims: `docs/specs/11-ai-terminal.md:1-230`.
- Product scope and later web-search and MCP work: `docs/ROADMAP.md:119-126`, `docs/ROADMAP.md:362-380`.
- UI rules: `docs/DESIGN.md:109-126`, `docs/DESIGN.md:169-203`.
- Current backend: `src/ai.zig:1-679`, `src/bridge.zig:12513-12730`, `src/integration_ai.zig:1-207`.
- Current frontend: `frontend/src/AiTab.tsx:1-130`, `frontend/src/types.ts:856-941`, `frontend/src/bridge.ts:596-608`, `frontend/src/App.tsx:1291-1295`, `frontend/src/test/mock-bridge.ts:859-863`, `frontend/index.html:5-8`.
- Native credential APIs and injection hook: the installed package root is selected at `build.zig:35`, with `@native-sdk/cli/src/runtime/system_services.zig:89-108`, `@native-sdk/cli/src/runtime/core.zig:754-769`, `@native-sdk/cli/src/runtime/api.zig:410-447`, `@native-sdk/cli/src/runtime/flow.zig:227-240`, and `@native-sdk/cli/src/platform/types.zig:239-241`, `@native-sdk/cli/src/platform/types.zig:2401-2403`, `@native-sdk/cli/src/platform/types.zig:2902-2914`.
- Runtime ownership: `src/main.zig:167-184`, `src/main.zig:216-236`, `src/runner.zig:470-521`.
- Installed Zig HTTP client: `/opt/homebrew/Cellar/zig/0.16.0_1/lib/zig/std/http/Client.zig:1-39`, `:790-871`, `:1115-1278`, `:1423-1480`, `:1649-1835`.

### External primary documentation

- [OpenAI API overview and authentication](https://developers.openai.com/api/reference/overview): API keys are secret, must not be exposed in client-side browser or app code, use Bearer authentication, and record request IDs without logging secrets.
- [Create a model response](https://developers.openai.com/api/reference/cli/resources/responses/methods/create): Responses request fields, `store`, `stream`, `previous_response_id`, the `reasoning.encrypted_content` include value, tool settings, output items, and terminal status.
- [Structured model outputs](https://developers.openai.com/api/docs/guides/structured-outputs): Responses `text.format` with `type: "json_schema"` and `strict:true`; schema output differs from function calling.
- [Streaming API responses](https://developers.openai.com/api/docs/guides/streaming-responses): semantic typed events such as `response.created`, `response.output_text.delta`, `response.completed`, and `error`.
- [Function calling](https://developers.openai.com/api/docs/guides/function-calling): `call_id`, JSON arguments, `function_call_output`, strict schemas, required properties, nullable optional values, and `parallel_tool_calls:false`.
- [Conversation state](https://developers.openai.com/api/docs/guides/conversation-state): with `store:false`, retain local history and append all response output items, including reasoning items, before the next request.
- [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data): Responses application-state retention, `store:false`, Zero Data Retention behavior, and the background-mode retention exception.
- [Safety in building agents](https://developers.openai.com/api/docs/guides/agent-builder-safety): keep untrusted values out of developer messages, constrain data with structured outputs, and keep approvals on.
- [Safety best practices](https://developers.openai.com/api/docs/guides/safety-best-practices): adversarial testing, human review for code, and bounded inputs and outputs.
- [WHATWG HTML server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html): UTF-8 event streams, line grammar, comments, multiple data lines, and event termination.
- [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility): partial OpenAI compatibility and its explicit Chat Completions and Responses limits.
- [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/): supported OpenAI routes and documented compatibility exceptions.

## Research conclusion

The current code is useful scaffolding, but it is not a partial end-to-end AI Terminal. The implementation should start only after Spec 11 adopts the native provider boundary, the runner-to-credential seam, the non-blocking context path, and the durable approval contract. These changes are prerequisites for an honest release claim, not optional hardening after the UI lands.
