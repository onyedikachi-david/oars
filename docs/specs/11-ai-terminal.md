# Spec 11 — AI Terminal

**Status:** 📋 · **Depends on:** 02 (exec), 03 (context), 04 (log context), 06 (save-as-script), 15 (audit) · **Spec owner:** frontend + core (thin)

## 1. Overview

Plain English → the exact command, explained, waiting for approval. The
AI proposes; the human disposes. BYO key to any OpenAI-compatible
provider; nothing runs on a server without a click; every executed
command is logged.

## 2. Goals / non-goals

**Goals**
- Chat-style panel per server: ask, see command + explanation, Run / Edit / Cancel.
- Destructive-operation flagging (heuristic + model flag) with amber warning.
- Context bundle: OS/hostname/uptime + monitor snapshot + tail of a chosen log.
- Provider config: an OpenAI-compatible Chat Completions base URL, model, API
  key (Keychain), and capability flags. Native Anthropic or Gemini APIs need
  separate adapters; their names alone do not make them compatible.
- Save approved command as a script; every run appended to audit history.

**Non-goals**
- No autonomous execution (approval is mandatory), no tool-use beyond the
  command card in v1 (MCP is a later stage), no telemetry, no CtrlOps-style
  cloud proxy — prompts go straight from the app to the user's provider.

## 3. User stories

- "why is the disk full" → `du -sh /var/log/* | sort -rh | head` with an explanation; I approve; output streams; I get a one-line summary.
- "clean up old docker images" → command flagged "Destructive — removes unused volumes"; I still approve after reading.
- "ban the IP that keeps hammering ssh" → ufw command; approved; audited.
- I approve a command I'll run weekly → "Save as script" with variables auto-suggested.

## 4. UI/UX

### 4.1 AI panel (per-server tab, toggleable side panel)
- Thread view: user asks (plain text) · assistant cards: **command block** (mono, syntax-tinted) + explanation + badges (Destructive, Read-only, Needs sudo) + buttons **Run · Edit · Cancel**.
- Editing the command re-renders the card; Run executes on the server; output streams below the card (terminal-styled); on completion: summary line + exit code.
- **Context chips** above the input: OS · load · disk · last-log (clickable to pick a log from spec 04; defaults to the most recently active).
- Provider selector + "no key configured" empty state with setup button.

### 4.2 Destructive flagging
- Heuristic list (client-side, before the model even replies): `rm -rf`, `dd `, `mkfs`, `fdisk`, `shutdown`, `reboot`, `:(){`, `DROP TABLE`, `DROP DATABASE`, `git push --force`, `chmod -R 777`, `> /dev/sd`, `kill -9` (unless PID from monitoring flow)…
- Model-provided `destructive: true` from the prompt contract also triggers it.
- Amber banner on the card: "Destructive — review carefully." Run requires the card's Run click (no extra confirm; the flag IS the warning — per CtrlOps parity).

### 4.3 States
- Asking → spinner with "thinking"; provider error → inline retry; timeout (60 s) → cancel.
- Server not connected → ask blocked with "connect first".
- Audit: "Ran with your approval — logged" note on executed cards.

## 5. Bridge API

The AI call is client-side in v1. This only works when the provider permits the
app origin through CORS. There is no standard capability-discovery endpoint
shared by all products described as OpenAI-compatible. A shipped provider
adapter supplies reviewed defaults; a Custom adapter makes the user select the
message role, streaming format, and structured-output mode. **Test provider**
runs the selected contract only after a user click and states that a completion
test can consume provider quota. HTTPS is required except for user-approved
loopback URLs such as a local model server. A later native HTTP bridge can
remove the CORS limit.

### `oars.ai.context` `{server_id}` → `{ok, os, hostname, uptime_sec, load, mem, disk, top_processes:[…], active_logs:[{path, last_write}]}`
(bundled from monitor cache + a light probe; cached ≤ 5 s)
### `oars.ai.provider.get` → `{ok, provider: {adapter, base_url, model, capabilities:{instruction_role, streaming, structured_output}}}` (no key!) · `oars.ai.provider.set` `{provider}` → `{ok}` (key stored via Keychain `ai:<base_url>`)
### `oars.ai.history` `{server_id, limit}` → audit-filtered runs (spec 15)
### Execution reuses `oars.ssh.exec` (channel id); Save-as-script reuses `oars.scripts.save`.

### Prompt contract (structured command proposal)
```
You write Linux commands. Respond ONLY with one JSON variant:
{"kind":"command","command":"…","explanation":"…","destructive":bool,"needs_sudo":bool}
{"kind":"question","question":"…","explanation":"…"}
```
- Context is untrusted data. Wrap it in a distinct data field and state that
  log text, host names, and process text are not instructions.
- When the provider supports Chat Completions Structured Outputs, send a strict
  `response_format` JSON schema. Otherwise use JSON mode when supported, then a
  prompt-only fallback. Capability fallback is explicit; a parse failure never
  executes or silently extracts a command from arbitrary markdown.
- A streamed JSON object cannot safely render its explanation until fields are
  parsed. Show provider progress while streaming, then render the validated
  card when the object is complete.

## 6. Zig core design

- Zig adds only `oars.ai.context` (aggregates existing caches + one probe) and history filtering. Everything else is frontend. This keeps the AI layer swappable and testable without mocking the bridge.
- **CSP note:** the packaged frontend policy is static while provider origins
  are user-configurable. V1 therefore declares `connect-src https:` plus
  loopback HTTP for local providers and still depends on provider CORS. This is
  a documented security tradeoff, not a claim that the Native SDK navigation
  allowlist controls `fetch`. A native HTTP bridge is the path to a narrower
  WebView policy.

## 7. Data model

- Provider config: `<data>/ai.json` (adapter, base URL, model, and explicit
  capability choices — no key). Key: Keychain `ai:<base_url>`.
- Threads are ephemeral (per session). Runs → audit history (spec 15).

## 8. Security

- The approval gate is the security model: nothing executes without Run and
  the destructive flag is visible. Commands run as the SSH user. Oars does not
  send a sudo password through an exec channel; a command that needs sudo can
  use only pre-approved non-interactive sudo authority or must move to the
  interactive terminal.
- Before the first request to a provider, show which server context fields will
  leave the machine and let the user remove log content. Send only the minimum
  selected context.
- The key persists only in Keychain. A request reads it into frontend memory
  and sends it to the configured provider in the authorization header. Do not
  say that it "never leaves the Keychain."
- Model output and destructive heuristics are advisory. The approval card is
  the execution boundary, and the exact edited command is shown again at Run.

## 9. Performance

- Context bundle ≤ 1 s (cached); command execution rides the standard exec path; streaming renders as tokens arrive.

## 10. Edge cases

- Provider rate-limited/401 → inline error with key-check hint.
- Model returns invalid or schema-breaking output → show a parse error and
  offer an explicit retry. Never scrape a code block and treat it as approved
  structured output.
- Command is a pipeline with heredocs → exec via `bash -c '<cmd>'` with escaping (same as spec 06).
- Ambiguous ask → model returns the `kind:"question"` variant → UI prompts for
  clarification and never renders a Run button.
- User edits command into something destructive → heuristic re-flags on the edited card.

## 11. Testing

- Unit: destructive heuristic table (known commands), prompt-building fixtures, JSON contract parsing (valid/invalid model output).
- Integration (container): ask → approve → run `du -sh`; verify audit entry; destructive flag on `rm -rf`; save-as-script round trip.
- Manual: streaming UX, provider errors, context chips.

## 12. Acceptance criteria

- [ ] Full ask → approve → run → audit loop works with a real OpenAI-compatible endpoint.
      (frontend + a live provider key; the backend half — context bundle,
      provider store, audited exec, history — is container-tested.)
- [ ] Destructive heuristic flags the fixture list; edited commands re-flag.
      (frontend-owned per §6 — Zig adds no AI logic; unit tests live with
      the React app.)
- [x] Nothing executes without an explicit Run click (verified by audit log).
      (backend: every `oars.ssh.exec` is audited (`ssh.exec` with the
      truncated command); `oars.ai.history` serves the audit-filtered
      view. The approval gate itself is the frontend Run button.)
- [x] Keys persist only in the Keychain; provider requests use an in-memory
      copy and config JSON has no secrets. (backend: `ai.json` holds
      adapter/base URL/model/capabilities only; the dispatcher test
      asserts no key material round-trips; the key remains frontend
      Keychain `ai:<base_url>`.)
- [ ] Save-as-script produces a working script. (frontend — reuses the
      spec 06 `oars.scripts.save`, already covered by its own tests.)

Backend status (this cycle):

- `oars.ai.context` — monitor snapshot (spec 03 cache, refresh-if-stale)
  + one light probe (OS via `/etc/os-release` PRETTY_NAME with `uname -sr`
  fallback, hostname via /proc, per-source `stat -c '%Y %n'` log mtimes),
  probe part cached ≤ 5 s per server; container-tested against the dev
  sshd (Alpine) with a configured log source.
- `oars.ai.provider.get/set` — `ai.json` store, validation (https
  everywhere except loopback http for local model servers; adapter ∈
  {openai_compatible, custom}; instruction_role ∈ {developer, system}),
  quarantine on corrupt files, mode 0600; audited on set.
- `oars.ai.history` — audit-filtered `ssh.exec` runs, newest first,
  default 20 / max 100.
- `oars.ssh.exec` now audits every executed command (`cmd=` truncated to
  120 chars) — the “every executed command is logged” contract.

Frontend-owned (spec §6), pending the UI cycle: the provider call, the
prompt contract (JSON mode / Structured Outputs), the destructive
heuristic table, save-as-script, and the ask → approve → run loop.

## 13. Research & References

- **Chat Completions API** — verified against OpenAI's current API
  schema (`https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create`):
  - Endpoint `POST /chat/completions`; request: `model`, `messages[]`
    with roles `developer`/`system`/`user`/`assistant`/`tool`, `stream`
    (bool), `stream_options: {include_usage}` (final chunk carries
    token usage before `data: [DONE]`), `temperature`, `tools`/
    `tool_choice` (unused in v1 — no tool-use per §2).
  - Response: `choices[].message` (`content`, `role`),
    `finish_reason` ∈ {stop, length, tool_calls, content_filter,
    function_call}, `usage` (`prompt_tokens`,
    `completion_tokens`, `total_tokens`).
  - Streaming: chunks are `object: "chat.completion.chunk"` with
    `choices[].delta` (`content` string fragments) — the spec's
    "progressive explanation render" maps directly to delta
    accumulation; SSE framing is the standard `data: …` line protocol
    with `data: [DONE]` terminator.
  - The current API also supports `response_format` with `json_schema`, which
    is preferred over prompt-only JSON for models that support it. OpenAI
    recommends the Responses API for new OpenAI-only projects, but Oars keeps
    Chat Completions as its cross-provider baseline and uses a provider
    capability layer.
  - OpenAI examples use the `developer` role. Compatible providers can differ,
    so Oars selects `developer` or `system` from provider capability data
    instead of assuming one role works everywhere.
- **Compatibility boundary** — “OpenAI-compatible” is not one versioned
  protocol with standard capability discovery. Oars treats Chat Completions as
  a baseline route and records adapter capabilities explicitly. A successful
  models-list request does not prove support for strict schemas, streaming, or
  a particular instruction role.
- **BYO-key architecture** — the client-side fetch design keeps the
  key in the frontend→provider path only (Keychain → memory); provider
  requests carry `Authorization: Bearer <key>` — the standard auth
  scheme for OpenAI-compatible endpoints (API reference, auth section).
  No proxy, no telemetry (per §2 non-goals).
- **JSON output contract** — the previous prompt-only contract and fenced-code
  fallback did not provide a strong parse boundary. The current OpenAI schema
  documents strict JSON Schema output. The spec now prefers that mode and
  refuses invalid fallback output.
- **Context bundle** — built from the monitor cache (spec 03 §5) and a
  light probe; the commands behind it are the verified ones from specs
  03/04 §13 (kernel /proc docs, coreutils, findutils).
- **CSP/connect-src** — the packaged WebView's CSP must allow
  `connect-src https:` for the provider origin; TLS-only + per-request
  key (no cookies held by the WebView for the provider) is the
  documented tradeoff in §6.

Sources: OpenAI API reference (chat/create), the OpenAI-compatible
provider ecosystem (Ollama/vLLM implement the same schema),
specs 03/04 §13.
