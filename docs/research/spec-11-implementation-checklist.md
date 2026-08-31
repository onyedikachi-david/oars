# Spec 11 implementation checklist

This checklist maps the frozen AI Terminal contract to its owning code and proof. It is not a release claim. An item stays open until its named automated test and, where required, desktop evidence pass on the current checkout.

## Contract ownership

| Requirement | Owner | Automated proof | Release proof | Status |
| --- | --- | --- | --- | --- |
| Provider metadata supports up to 16 revisioned OpenAI Responses or Chat Completions profiles, and never persists secrets | `src/ai/provider.zig` | Provider validation, migration, atomic save, quarantine, revision, and secret-scan tests | Provider setup fixtures | Open |
| Provider URLs reject credentials, queries, fragments, non-HTTPS remote hosts, ambiguous loopback names, and unsafe path composition | `src/ai/provider.zig`, `src/ai/transport.zig` | URL table tests and endpoint composition tests | Local provider matrix | Open |
| API keys enter through native secure entry and remain under `ai:<provider_id>` in the platform credential store | `src/ai/credentials.zig`, `src/main.zig`, `src/bridge.zig` | Facade tests with a fake credential service | Null-platform credential integration and secret scan | Open |
| Worker threads receive a bounded copied secret and never retain a runtime pointer | `src/ai/credentials.zig`, `src/ai/coordinator.zig` | Thread-affinity, copy, secure-clear, and oversize tests | Cancel and restart matrix | Open |
| Bridge handlers never run SSH or provider network work | `src/bridge.zig`, `src/ai/coordinator.zig`, `src/sessions.zig` | Admission-only bridge tests and asynchronous context tests | Desktop responsiveness during slow provider and SSH fixtures | Open |
| Context refresh is asynchronous, cached for at most five seconds, bounded, cancellable, and cursor-polled | `src/ai/coordinator.zig`, `src/sessions.zig` | Context lifecycle, bounds, cancel, disconnect, and independent-cursor tests | SSH container context fixture | Open |
| Provider HTTP/TLS, authentication, retry classification, body limits, and timeouts are native-owned | `src/ai/transport.zig` | Request-shape, header/body cap, timeout, retry, redaction, and status mapping tests | Pinned Ollama/vLLM and live OpenAI checks | Open |
| SSE accepts CRLF and split fields, ignores comments and unknown events, enforces event and stream caps, and reports terminal failures | `src/ai/sse.zig` | Fragmentation, CRLF, multiline data, unknown event, EOF, overflow, and error tests | Local provider streaming fixture | Open |
| Responses requests set `stream`, `store:false`, `background:false`, strict `text.format`, no tools, and request encrypted reasoning content | `src/ai/responses.zig` | Golden request and semantic-event parser tests | Live OpenAI Responses run | Open |
| Chat Completions remains a separate adapter with its own request and stream schema | `src/ai/chat.zig` | Golden request, `[DONE]`, refusal, malformed output, and finish-reason tests | Pinned Ollama/vLLM run | Open |
| Threads hold at most 50 turns, messages and continuation state stay bounded, and complete provider output items are replayed for stateless continuation | `src/ai/coordinator.zig`, `src/ai/responses.zig` | Thread cap, turn cap, 16 KiB message, 512 KiB continuation, and reasoning replay tests | Multi-turn live provider check | Open |
| Every provider POST is journaled and fsynced before dispatch, and uncertain outcomes are never retried automatically | `src/ai/journal.zig`, `src/ai/coordinator.zig` | Write-order, crash point, partial-tail, duplicate, and recovery-state tests | Kill/restart provider matrix | Open |
| Turn and context streams use versioned non-destructive cursors with explicit dropped-byte and terminal state | `src/ai/coordinator.zig`, `src/bridge.zig` | Independent-reader, stale-cursor, overflow, EOF, and schema-version tests | Desktop dual-reader fixture | Open |
| Structured output is parsed into a bounded explanation, optional question, and exact command proposal; the model has no execution authority | `src/ai/proposal.zig` | Schema, refusal, extra-field, command-size, and hostile-output tests | Malformed-output fixture | Open |
| A proposal freezes its ID, revision, hash, server, connection generation, provider revision, expiry, and destructive acknowledgement | `src/ai/proposal.zig`, `src/ai/coordinator.zig` | Edit/refreeze, hash, stale server/provider/connection, expiry, and acknowledgement tests | Approval-state desktop fixtures | Open |
| Approval is journaled and fsynced before SSH admission, then the exact frozen command runs through tracked SSH execution | `src/ai/journal.zig`, `src/ai/coordinator.zig`, `src/sessions.zig` | Admission ordering, exact-byte command, one-shot admission, audit, and history tests | SSH container exact-command check | Open |
| Cancellation distinguishes requested, confirmed, and outcome-unknown states for provider and SSH work | `src/ai/coordinator.zig`, `src/sessions.zig` | Cancel-before-send, cancel-in-flight, post-admission cancel, and late-completion tests | Slow-provider and slow-SSH matrix | Open |
| Restart recovery exposes interrupted pre-dispatch, uncertain provider, awaiting approval, admitted SSH, and terminal records honestly | `src/ai/journal.zig`, `src/ai/coordinator.zig` | Recovery matrix and idempotent replay tests | Process kill/restart matrix | Open |
| The React client uses exact bridge types and implements provider setup, context disclosure, thread/turn streaming, proposal editing, approval, output, cancel, and recovery states | `frontend/src/types.ts`, `frontend/src/bridge.ts`, `frontend/src/AiTab.tsx` | Type check and component tests for every fixture in `docs/NEXT-SPEC.md` | Desktop and narrow light/dark review | Open |
| AI context is bound to the selected server and never silently falls back to the first fleet entry | `frontend/src/App.tsx`, `frontend/src/AiTab.tsx` | Server-selection and disconnect tests | Multi-server desktop fixture | Open |
| Long context is summarized only after disclosure and explicit approval, with the exact sent payload available for review | `src/ai/coordinator.zig`, `frontend/src/AiTab.tsx` | Summary admission, disclosure, refusal, and cap tests | Summary desktop fixture | Open |
| A frozen proposal can be saved to Scripts without bypassing the Scripts validation contract | `frontend/src/AiTab.tsx`, `frontend/src/ScriptsTab.tsx` | Handoff payload and validation tests | AI-to-Scripts desktop flow | Open |

## Fixed bounds

The implementation and tests must use the values frozen in `docs/NEXT-SPEC.md`: 16 providers, 100 threads, 50 turns per thread, 16 KiB messages, 64 KiB commands, 8 KiB explanations and questions, 64 KiB logs, 128 KiB request bodies, 64 KiB response headers, 256 KiB SSE events, 128 KiB structured output, 8 KiB error bodies, 1,024 events or 1 MiB retained stream data, 512 KiB continuation state, two total provider requests, one provider request per thread, and 4,096-byte secrets.

## Validation gates

- [x] Clean baseline: Zig build, Zig tests, frontend tests, TypeScript, frontend production build, and the current integration harness.
- [x] Zig format, build, unit tests, contract tests, and `git diff --check` pass after implementation: 336 passed and one environment-gated test skipped on 2026-08-31.
- [x] Frontend test, TypeScript, and production build pass after implementation: 42 files and 506 tests passed on 2026-08-31.
- [ ] Native AI credential lifecycle passes: the provider key enters through native secure entry, stays out of React/WebView state and every bridge response, and is absent from logs, journals, and persisted JSON.
- [ ] Pinned local provider fixtures pass for Responses and Chat Completions, including malformed SSE, disconnect, timeout, refusal, oversize, and cancel cases.
- [x] SSH container passes context, proposal edit, stale revision and warning rejection, approval ordering, idempotent exact execution, output completion, audit, and history cases.
- [x] SSH container passes verified process-group cancellation with a child process and disconnect recovery without command replay.
- [ ] Live OpenAI Responses validation passes with the current API contract.
- [ ] Process kill/restart recovery passes at every journal boundary.
- [x] Desktop and narrow layouts pass in light and dark themes for all 17 frozen fixtures; the 68-case review is recorded in `docs/research/spec-11-browser-evidence.md`.
- [ ] A final repository secret scan is clean.
