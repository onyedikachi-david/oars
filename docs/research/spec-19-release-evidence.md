# Spec 19 Release Evidence: Conversational AI and Reviewed Tools

Date: 2026-09-01
Target: Spec 19 (`docs/specs/19-ai-chat-tools.md`)
Status: Partial

## Implemented and locally verified

- Providers persist an explicit `native_function` or `structured_result` tool
  mode. A native capability test forces exactly `run_server_command` and fails
  when the provider returns prose or an invalid call.
- Responses and Chat Completions parse one bounded, strict native tool call.
  They reject missing, changed, duplicate, parallel, malformed, oversized, and
  incomplete call identity or arguments.
- One validated call becomes the existing frozen proposal. It cannot run until
  the operator approves the exact command through the native SSH path.
- An output continuation binds the selected execution, provider revision,
  credential generation, connection identity, call ID, tool name, cursor
  range, exit status, and disclosed bytes. Oars journals that selection before
  the continuation POST.
- Operation replay returns the durable continuation admission before it reads
  retained output again. A restart restores the selected result and marks an
  in-flight continuation interrupted without resending it.
- Assistant preambles survive snapshot and journal recovery. Switching a Chat
  provider to native tools removes the incompatible structured-output option.

## Current automated evidence

The 2026-09-01 review added focused regressions for provider capability,
fragmented stream identity, exact call/result binding, journal ordering,
restart recovery, assistant preamble recovery, and adapter-switch metadata.

The current local results are:

- `zig build test --summary all`: 360 of 361 tests passed. One live-SSH test
  was skipped by its environment gate.
- `zig build --summary all`: all 8 build steps passed.
- `cd frontend && npx tsc --noEmit`: passed.
- `cd frontend && npm test -- --run`: 42 files and 513 tests passed.
- `cd frontend && npm run build`: passed. Vite reported its existing large
  chunk warning.
- `./scripts/integration-test.sh`: passed against the Docker SSH and MinIO
  fixtures.

Run the full gate from the repository root:

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

Record the final counts and environment-gated skips in the delivery note for
the branch. A skipped external gate stays open; it is not a pass.

## Open release evidence

- [ ] Run canceled, denied, unavailable, configure, replace, use, delete, and
      shutdown credential cases against the real macOS Keychain and the
      supported Linux credential backend. Scan WebView state, bridge results,
      logs, journals, audit, history, and persisted JSON for the secret sentinel.
- [ ] Run one real local Responses-compatible provider and one real
      Chat-compatible provider through ask, reviewed call, approval, real SSH
      execution, explicit result disclosure, and assistant prose.
- [ ] Force process restart after call persistence, approval, SSH admission,
      execution completion, tool-result persistence, continuation request
      start, and continuation response creation. Confirm that no provider POST
      or SSH command repeats.
- [ ] Scan all retained and persisted surfaces for an undisclosed-output
      sentinel. Confirm that only the selected bounded output reaches the
      approved continuation request.
- [ ] Complete keyboard-only, screen-reader status, narrow layout, light and
      dark theme, and reduced-motion checks in the packaged desktop app.
- [ ] Build, install, launch, upgrade, and remove the supported macOS and Linux
      packages and record platform-specific results.

## Acceptance status

The source and automated contracts are implemented. Spec 19 remains Partial
until every open item above has current, reproducible evidence. Do not change
the spec to Complete because a required desktop or real-provider gate was
skipped.
