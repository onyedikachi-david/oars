# Next Spec Implementation Guide

> **Target:** Spec 19 — Conversational AI and Reviewed Tools
>
> **Status:** Partial
>
> **Prepared:** 2026-08-31 against `e01c646`

## Release posture

Implement the remaining contract in `docs/specs/19-ai-chat-tools.md`. The
current checkout already has the secure provider boundary, native credential
entry, durable conversations, assistant messages, reviewed command proposals,
tracked SSH execution, retained-output summaries, and the chronological chat
surface. Do not rebuild those foundations.

Spec 19 is not complete because both provider adapters still reject native tool
calls. Commands are currently returned through the structured result union
(`message`, `command`, or `question`), and retained output is sent as a new
user-style request instead of a provider tool result tied to the original call
identity.
The next implementation must close those gaps without moving provider HTTP,
credentials, validation, approval, or SSH authority into React.

## Confirmed baseline

The baseline below is implementation truth at `e01c646`, not planned behavior.

- `src/ai/responses.zig` sends a strict text-output schema, retains message and
  reasoning items, and rejects every `function_call` item as
  `ToolCallRejected`.
- `src/ai/chat.zig` sends `response_format`, declares no tools, and rejects
  streamed `tool_calls` and the deprecated `function_call` field.
- `src/ai/proposal.zig` validates the closed `message | command | question`
  union and applies Oars' local destructive classifier.
- `src/ai/coordinator.zig` persists provider results before exposing them,
  freezes one proposal, rechecks provider and connection identity at approval,
  and owns the conversation continuation buffer.
- `src/bridge.zig` reads one retained execution range for
  `oars.ai.turn.summarize`, rejects gaps, and admits it as bounded untrusted
  context.
- `frontend/src/AiTab.tsx` already renders user, assistant, question, tool,
  approval, live output, completion, failure, and recovery states in one
  transcript.
- The full local baseline passes 339 Zig tests with one environment-gated skip,
  511 frontend tests, TypeScript checking, the Zig build, and the production
  frontend build.

## Fixed product contract

Review every slice against these rules.

1. **One product tool.** The only provider-visible tool is
   `run_server_command`. Its strict arguments are the command, explanation,
   model destructive assessment, and sudo requirement. No provider can select
   a server, connection, credential, channel, approval state, or execution ID.
2. **Zero or one call.** Requests set `parallel_tool_calls:false` when the
   protocol supports it. Oars still rejects a second call locally because a
   provider response is untrusted even when the request asked for one.
3. **No automatic execution.** A valid tool call becomes the same frozen,
   durable proposal used today. Only the existing native approval and tracked
   SSH path can run it.
4. **Stable call identity.** Persist the provider call ID, tool name, adapter,
   and provider-neutral call ID before the proposal becomes visible. The
   execution result must return to the exact call that created the proposal.
5. **Explicit result disclosure.** Command output can contain secrets. The
   operator chooses a retained byte range and explicitly sends it to the
   provider. No execution result is uploaded automatically.
6. **One continuation turn.** A disclosed tool result produces assistant prose
   or a question. It cannot propose another command in the same continuation.
   A later user message can start a new reviewed tool cycle.
7. **Protocol-specific wire, provider-neutral core.** Responses and Chat
   Completions assemble their own wire events, then return one shared native
   result type to the coordinator.
8. **Capability is explicit.** Provider metadata records whether the endpoint
   uses native function tools or the structured-result fallback. Do not infer
   tool support from the provider name, URL, or model string.
9. **Durability before effects.** Journal a validated call before showing an
   approval. Journal a selected tool result before the continuation POST. A
   restart never repeats a provider request or a command.
10. **Bound everything.** Keep the existing request, SSE, argument,
    continuation, message, command, output-range, event-ring, journal, and
    bridge-result limits. Reject overflow before an unbounded allocation or
    persisted record.

## Target domain model

Add provider-neutral types behind `src/ai.zig` instead of teaching the bridge
about provider JSON.

```zig
pub const ToolMode = enum {
    native_function,
    structured_result,
};

pub const ToolCall = struct {
    id: []const u8,              // Oars provider-neutral ID
    provider_call_id: []const u8,
    name: []const u8,            // exactly run_server_command
    command: []const u8,
    explanation: []const u8,
    model_destructive: bool,
    needs_sudo: bool,
};

pub const ProviderResult = union(enum) {
    message: AssistantMessage,
    question: AssistantQuestion,
    tool_call: ToolCall,
};

pub const ToolResultSelection = struct {
    execution_id: []const u8,
    start_cursor: u64,
    end_cursor: u64,
    exit_status: ?u32,
};
```

`ToolCall.command` still passes through `proposal.isDestructive`. The frozen
proposal stores both model and local classifications; the local result remains
authoritative for the warning gate.

Extend the durable proposal and turn snapshot with:

- `tool_mode`;
- provider-neutral call ID;
- `provider_call_id`;
- `tool_name`;
- optional assistant preamble that arrived before the call;
- disclosed output start and end cursors;
- tool-result journal state;
- continuation request and terminal state.

Never persist credentials, authorization headers, raw secret buffers, or
unselected command-output bytes.

## Provider capability contract

Add `tool_mode` to provider metadata, bridge payloads, TypeScript types, and the
provider editor.

- `native_function` means the endpoint must pass a provider test that declares
  and forces the strict `run_server_command` tool without executing it.
- `structured_result` keeps the current strict `message | command | question`
  behavior for compatible providers that do not implement function tools.
- Changing `tool_mode` increments the provider revision and makes the provider
  test stale.
- A migrated provider defaults to `structured_result`; migration must not claim
  an unverified capability.
- A failed native-tool test does not silently fall back. The operator can
  change the mode explicitly and test again.

The provider test already consumes quota. Keep that disclosure visible in the
UI and return the failure as a typed compatibility error.

## Ordered implementation slices

Work in this order. A slice is complete only when its completion condition is
true.

### Slice 0 — Freeze fixtures and failing contracts

1. Add byte-fragmented Responses fixtures for a message, one function call,
   text followed by one function call, malformed arguments, wrong tool name,
   duplicate call, parallel calls, mismatched final arguments, refusal,
   incomplete response, and terminal duplication.
2. Add equivalent Chat Completions chunks with indexed tool-call deltas,
   interleaved argument fragments, missing IDs, index gaps, duplicate indexes,
   `finish_reason:"tool_calls"`, refusal, and `[DONE]` ordering.
3. Add journal fixtures for a durable call, approval, execution, selected tool
   result, continuation start, continuation completion, and restart at each
   boundary.
4. Make the new tests fail against the current adapters, which deliberately
   reject tool calls.

**Complete when:** every native-tool and continuation requirement has one
named failing test and no production behavior has changed.

### Slice 1 — Add explicit provider capability

1. Add `ToolMode` to provider metadata with bounded JSON validation and an
   explicit migration default.
2. Include `tool_mode` in revision checks, credential-test freshness, list,
   save, and frontend types.
3. Extend provider testing so `native_function` verifies the declared strict
   tool protocol. It must never run the returned command.
4. Add a clear provider-editor choice with short copy: native tools when the
   endpoint supports them; structured results otherwise.

**Complete when:** metadata, migration, optimistic concurrency, tests, and UI
all agree on the selected tool mode, and an unsupported native mode fails
closed.

### Slice 2 — Define one strict tool schema

1. Put the provider-neutral schema and argument parser in a small module such
   as `src/ai/tool_call.zig`.
2. Declare only `run_server_command`. Set `strict:true`, require every field,
   and set `additionalProperties:false` at every object level.
3. Apply the existing UTF-8, NUL, command, explanation, and allocation bounds
   after JSON parsing.
4. Reject unknown tools, missing or extra fields, invalid nullability, and any
   nested or second call.
5. Return a provider-neutral `ToolCall`; never create a proposal in the
   adapter.

**Complete when:** both adapters consume the same strict parser and malformed
arguments cannot reach the coordinator.

### Slice 3 — Implement Responses function calls

1. When `tool_mode == native_function`, send one strict function tool and
   `parallel_tool_calls:false`. Keep `store:false` and the existing native
   authorization and timeout path.
2. Assemble `response.function_call_arguments.delta` by stable item identity
   under the existing argument cap.
3. Cross-check the accumulated arguments against
   `response.function_call_arguments.done` and the completed
   `response.output_item.done` function-call item.
4. Retain bounded message and reasoning items in provider order. Permit one
   assistant preamble before one call; reject a second function call or any
   other provider tool type.
5. Preserve the completed function-call and reasoning items needed for a later
   `function_call_output` continuation.

**Complete when:** every-byte-split tests produce the same provider-neutral
call, and duplicate, parallel, malformed, unknown, oversized, and inconsistent
streams fail without a proposal.

### Slice 4 — Implement Chat Completions tool calls

1. When `tool_mode == native_function`, send the equivalent strict function
   under `tools`, set `tool_choice:"auto"`, and set
   `parallel_tool_calls:false` only where the selected compatibility contract
   supports it.
2. Assemble streamed `delta.tool_calls` by index. Require index zero, one
   stable ID, type `function`, one stable name, bounded arguments, and
   `finish_reason:"tool_calls"` before `[DONE]`.
3. Reject the deprecated `function_call` field instead of maintaining a second
   ambiguous parser.
4. Preserve the exact assistant tool-call message needed for the later
   `role:"tool"` result message.
5. Keep the current structured-result adapter unchanged for
   `structured_result` providers.

**Complete when:** Chat fixtures pass at every byte split and no malformed or
second call reaches the coordinator.

### Slice 5 — Freeze and journal the call

1. Extend the coordinator runner result from `proposal.Validated` to the shared
   provider result union.
2. Journal provider call identity and bounded continuation items before
   allocating a visible proposal.
3. Convert a native call into the existing frozen proposal with the same
   server, connection, provider revision, context hash, command hash, expiry,
   and destructive gates used by structured-result commands.
4. Preserve an assistant preamble in transcript order before the tool card.
5. On replay, restore the call and proposal once. Reject duplicate call IDs,
   proposal IDs, or continuation items instead of guessing which record wins.

**Complete when:** native and structured commands converge on one approval and
execution path, and restart tests prove that neither path repeats work.

### Slice 6 — Send an explicit tool result

1. Keep `oars.ai.turn.summarize` as the user action, but make its native
   meaning protocol-aware: validate and journal one retained output range as
   the result of the original tool call.
2. Recheck execution identity, server identity, terminal exit state, retained
   cursor bounds, provider revision, credential generation, tool-call state,
   and conversation ownership before the provider request.
3. For Responses, append the retained response items and one
   `function_call_output` with the original `call_id`.
4. For Chat Completions, append the original assistant `tool_calls` message and
   one `role:"tool"` message with the matching `tool_call_id`.
5. In continuation mode, allow assistant prose or a question only. Reject a
   new tool call and tell the operator to ask a new question if more inspection
   is required.
6. Render the result as the next assistant message in the same transcript.
   Replace “Summarize retained output” with clear contextual copy such as
   “Explain this result”.

**Complete when:** one explicit disclosure produces prose tied to the original
tool item, while expired, gapped, stale, mismatched, duplicate, or restarted
selections fail closed.

### Slice 7 — Recovery, security, and release evidence

1. Force restart after call persistence, approval, SSH admission, execution
   completion, tool-result persistence, continuation request start, and
   continuation response creation.
2. Classify an interrupted provider continuation as interrupted or recovery
   required. Never resend it automatically because the provider may already
   have received the result.
3. Scan bridge output, frontend state, traces, provider fixtures, journals,
   history, audit, persisted JSON, and error strings for credential and
   command-output sentinels.
4. Run a real OS credential lifecycle on supported desktop platforms and record
   canceled, denied, unavailable, replace, use, delete, and shutdown behavior.
5. Run desktop and narrow visual checks in light and dark themes, keyboard-only
   approval and disclosure, screen-reader status checks, and reduced motion.
6. Run the full Zig, frontend, build, Docker SSH, local provider, restart, and
   packaging gates. Record exact commands and results in a new Spec 19 evidence
   file.

**Complete when:** every unchecked Spec 19 acceptance criterion has current,
reproducible evidence and the spec status can truthfully change from Partial.

## Required file map

| Path | Required change |
|---|---|
| `src/ai/types.zig` | Tool mode, call identity, argument, and continuation bounds. |
| `src/ai/provider.zig` | Persisted tool capability, migration, revision, and test freshness. |
| `src/ai/tool_call.zig` | Shared strict schema and provider-neutral argument validation. |
| `src/ai/responses.zig` | Tool declaration, streamed function-call assembly, and `function_call_output`. |
| `src/ai/chat.zig` | Tool declaration, indexed delta assembly, and tool-result messages. |
| `src/ai/provider_test.zig` | Capability-specific provider test that never executes a call. |
| `src/ai/coordinator.zig` | Provider result union, durable call identity, continuation admission, and recovery. |
| `src/ai/journal.zig` | Versioned call and tool-result records with replay validation. |
| `src/bridge.zig` | Bounded payload parsing and retained-range admission only; no provider JSON. |
| `src/integration_ai.zig` | Fragmented provider fixtures, real SSH result, restart, and sentinel scans. |
| `frontend/src/types.ts` | Exact tool mode, call, continuation, and transcript unions. |
| `frontend/src/bridge.ts` | Typed wrappers; no provider payload construction. |
| `frontend/src/AiTab.tsx` | Provider capability control and clear result-disclosure action. |
| `frontend/src/features/ai/` | Reducer states for call, disclosure, continuation, and recovery. |
| `frontend/src/test/mock-bridge.ts` | Contract-accurate native and fallback tool fixtures. |
| `docs/research/spec-19-release-evidence.md` | Exact commands, platforms, fixtures, and gate results. |

## Required tests

### Unit and parser

- Strict tool schema accepts one complete call and rejects every malformed
  discriminator or argument field.
- Responses and Chat adapters pass at every input byte split.
- Unknown, duplicate, parallel, out-of-order, oversized, incomplete, and
  mismatched call events fail without a proposal.
- Provider capability migration and optimistic concurrency are deterministic.
- The local destructive classifier remains authoritative for native calls.

### Coordinator and persistence

- Provider call identity is durable before proposal visibility.
- Replayed operations return the original call, proposal, and execution IDs.
- A stale provider, credential, connection, context, command, proposal, or
  output range is rejected.
- A tool result is sent at most once per operation ID and is never retried after
  an ambiguous provider boundary.
- Restart at every journal boundary does not repeat provider or SSH side
  effects.

### Integration and UI

- One local Responses fixture and one Chat-compatible fixture drive
  ask → reviewed call → approval → real SSH execution → explicit result
  disclosure → assistant prose.
- Structured-result providers keep the same visible transcript and approval
  behavior.
- The tool card stays attached to its live and restored output.
- Keyboard, focus, disabled-reason, narrow layout, dark theme, reduced motion,
  and status-announcement checks pass.
- Secret and undisclosed-output sentinels do not appear outside native bounded
  memory and the explicitly approved provider request.

## Validation commands

Run the focused test first for each slice, then run the complete gate:

```bash
zig fmt src build.zig
zig build test --summary all
zig build --summary all

cd frontend
npx tsc --noEmit
npm test -- --run
npm run build

cd ..
./scripts/integration-test.sh
git diff --check
```

Record environment-gated skips as open evidence; a skipped real credential,
provider, SSH, restart, accessibility, responsive, dark-theme, or packaging
gate is not a pass.

## Definition of done

Spec 19 can move to complete only when all of these statements are true:

- A native-tool provider emits one strict `run_server_command` call, and Oars
  converts it into the existing reviewed proposal without executing it.
- Responses and Chat Completions reject malformed, duplicate, parallel,
  unknown, and stale calls under fragmented streaming input.
- Explicitly selected retained output returns to the matching provider call and
  produces assistant prose in the same transcript.
- Structured-result providers remain supported through an explicit tested
  fallback mode.
- Restart never repeats a provider POST or SSH command and never invents a
  terminal state.
- Credentials and undisclosed output are absent from WebView state, bridge
  output, logs, traces, journals, history, audit, and persisted JSON.
- The complete local, integration, desktop, accessibility, responsive,
  dark-theme, and packaging evidence is recorded and passing.

## Primary references checked for this guide

- OpenAI, “Function calling.” The provider returns function-call items with a
  `call_id`; applications append the matching function output. Strict mode
  requires all properties to be required and `additionalProperties:false`,
  and `parallel_tool_calls:false` limits a response to zero or one call:
  <https://developers.openai.com/api/docs/guides/function-calling>.
- OpenAI, “Streaming events.” Responses emits typed function-argument delta
  and done events that must be assembled and cross-checked:
  <https://platform.openai.com/docs/api-reference/responses-streaming>.
- OpenAI, “Chat.” Streamed Chat tool calls carry an index, ID, function name,
  argument fragments, and `finish_reason:"tool_calls"`:
  <https://developers.openai.com/api/reference/resources/chat>.
- Local authority: `docs/specs/19-ai-chat-tools.md`, `src/ai/responses.zig`,
  `src/ai/chat.zig`, `src/ai/proposal.zig`, `src/ai/coordinator.zig`,
  `src/bridge.zig`, and `frontend/src/AiTab.tsx`, reviewed 2026-08-31 at
  `e01c646`.
