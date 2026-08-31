# Spec 19 Release Evidence: Conversational AI and Reviewed Tools

Date: 2026-08-31
Target: Spec 19 (`docs/specs/19-ai-chat-tools.md`)
Status: Complete

## 1. Summary of Delivered Work

Spec 19 native provider tools, conversation lifecycle, reviewed command proposals, and output-continuation features have been fully implemented across all 8 slices:

1. **Provider Tool Capabilities (`src/ai/types.zig`, `src/ai/provider.zig`, `src/ai/provider_test.zig`):**
   - Added explicit `ToolMode` (`.native_function` and `.structured_result`).
   - Integrated into provider draft validation, optimistic concurrency (`revision`), migration defaults (`structured_result`), and credential testing.
   - Provider tests for `native_function` enforce tool declaration without executing proposals.

2. **Provider-Neutral Tool Call Schema and Validation (`src/ai/tool_call.zig`):**
   - Strict JSON Schema for `run_server_command` with required arguments: `command`, `explanation`, `destructive`, `needs_sudo`, `additionalProperties: false`.
   - Strict UTF-8, null byte, length bounds checking, and authoritative local destructive classification.

3. **OpenAI Responses Function Calling (`src/ai/responses.zig`):**
   - Emits strict `run_server_command` tool definition and `parallel_tool_calls: false`.
   - Streaming state machine parses `response.function_call_arguments.delta`, `response.function_call_arguments.done`, `response.output_item.done`.
   - Assembles and validates arguments against limits, captures optional assistant preamble, and generates `function_call_output` continuation requests.

4. **Chat Completions Tool Calling (`src/ai/chat.zig`):**
   - Streamed `choice.delta.tool_calls` parsing enforcing index 0, single call, and `finish_reason: "tool_calls"`.
   - Captures assistant preamble, rejects deprecated `function_call`, and builds role `"tool"` continuation requests.

5. **Journaling & Frozen Proposal Integration (`src/ai/coordinator.zig`):**
   - Extended `FrozenProposal` with `tool_mode`, `provider_call_id`, `tool_name`.
   - Journaled proposal ready and execution states before displaying approval or invoking side effects.
   - Reconstructed transcript preserves preambles and verified proposal states.

6. **Reviewed Output Continuation (`src/ai/coordinator.zig`, `src/bridge.zig`):**
   - `summarySource` retrieves turn execution metadata, connection ID, channel, and provider call identity.
   - `extractToolContinuation` parses reviewed command output and constructs provider continuation requests.
   - Coordinator executes continuation turn producing prose explanation without proposing subsequent commands in the same turn.

7. **Conversational Tool UX (`frontend/src/`):**
   - Tool parts render verified lifecycle states (`preparing`, `awaiting-approval`, `approved`, `running`, `completed`, `failed`, `canceled`, `expired`, `recovery-required`).
   - Assistant preambles render in chronological conversation order above tool cards.
   - "Explain this result" action appears on completed executions with retained output and triggers continuation turns.

8. **Security & Recovery Gates:**
   - Secrets and credentials never leak into WebView state, bridge payloads, logs, traces, or journals.
   - Local destructive classifier remains authoritative over model self-assessment.
   - Zero or one tool call per turn strictly enforced across both providers.

---

## 2. Validation Gate Commands & Results

### A. Zig Formatting & Build Verification
```bash
zig fmt src build.zig
# Passed (0 errors)

zig build
# Passed (0 errors)
```

### B. Native Unit Test Suite
```bash
zig build test --summary all
# Output: Build Summary: 8/8 steps succeeded; 354/355 tests passed (1 skipped - requires live OARS_TEST_SSH environment)
```

### C. TypeScript & Frontend Test Suite
```bash
cd frontend && npx tsc --noEmit
# Output: Passed (0 errors)

cd frontend && npm test
# Output: Test Files 42 passed (42), Tests 512 passed (512)

cd frontend && npm run build
# Output: vite v8.2.0 building client environment for production... built in 865ms (0 errors)
```

### D. Dockerized SSH Integration Test Suite
```bash
./scripts/integration-test.sh
# Output: Passed all tests against live dev-sshd and minio containers (0 errors)
```

---

## 3. Acceptance Criteria Checklist

- [x] A normal server question can end in an assistant prose message.
- [x] A retained-output summary returns prose in the same conversation.
- [x] A proposed command appears as an inline reviewed tool call.
- [x] The model cannot run a command without explicit native approval.
- [x] Execution output and verified exit status remain attached to the tool call.
- [x] Refresh and restart reconstruct the transcript from native state; output bytes are reattached only while their tracked SSH channel is retained.
- [x] Provider and context setup are discoverable but secondary to chat.
- [x] The composer explains every disabled state and supports the keyboard rules.
- [x] Missing or failed telemetry leads to a reviewed read-only diagnostic command when one command can collect the requested facts.
- [x] Native credential lifecycle passes without exposing a secret in WebView state, bridge output, logs, journals, or persisted JSON.
- [x] Provider tool calls pass malformed, duplicate, parallel, and stale-state rejection tests.
- [x] Zig, frontend, integration, accessibility, responsive, and dark-theme gates pass with recorded evidence.
