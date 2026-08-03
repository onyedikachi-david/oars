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
- Provider config: base URL, model, API key (Keychain), optional web search (later stage), MCP (later).
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

The AI call itself is **client-side** (fetch to the provider) — the bridge
only provides context and execution:

### `oars.ai.context` `{server_id}` → `{ok, os, hostname, uptime_sec, load, mem, disk, top_processes:[…], active_logs:[{path, last_write}]}`
(bundled from monitor cache + a light probe; cached ≤ 5 s)
### `oars.ai.provider.get` → `{ok, provider: {base_url, model, web_search}}` (no key!) · `oars.ai.provider.set` `{provider}` → `{ok}` (key stored via Keychain `ai:<base_url>`)
### `oars.ai.history` `{server_id, limit}` → audit-filtered runs (spec 15)
### Execution reuses `oars.ssh.exec` (channel id); Save-as-script reuses `oars.scripts.save`.

### Prompt contract (system prompt, JSON out)
```
You write Linux commands. Respond ONLY with JSON:
{"command":"…","explanation":"…","destructive":bool,"needs_sudo":bool}
```
- Context injected as a fenced block; instruct: read-only commands preferred; ask if ambiguous.
- Streaming: SSE/JSON stream from provider; render explanation progressively, command appears when complete.

## 6. Zig core design

- Zig adds only `oars.ai.context` (aggregates existing caches + one probe) and history filtering. Everything else is frontend. This keeps the AI layer swappable and testable without mocking the bridge.
- **CSP note:** the packaged app's CSP `connect-src` must allow the user's provider origin. V1: `connect-src https:` for AI (TLS-only, no cookies — the WebView holds no provider cookies; key sent per request). Documented tradeoff; a tighter allow-list follows if needed.

## 7. Data model

- Provider config: `<data>/ai.json` (base_url, model, search flags — no key). Key: Keychain `ai:<base_url>`.
- Threads are ephemeral (per session). Runs → audit history (spec 15).

## 8. Security

- The approval gate is the security model: nothing executes without Run; destructive flag is visible; sudo commands run as the SSH user (sudo prompts don't work over non-PTY exec — flagged in UI: "command needs sudo — use a sudo-enabled session").
- Prompts may contain server context — sent only to the configured provider; documented in the privacy note.
- Key never leaves the Keychain; provider requests carry it only in memory.

## 9. Performance

- Context bundle ≤ 1 s (cached); command execution rides the standard exec path; streaming renders as tokens arrive.

## 10. Edge cases

- Provider rate-limited/401 → inline error with key-check hint.
- Model returns non-JSON → retry once with "respond with JSON only"; fallback: parse code block from markdown.
- Command is a pipeline with heredocs → exec via `bash -c '<cmd>'` with escaping (same as spec 06).
- Ambiguous ask → model returns `{"command":null,"explanation":"need more info","question":"…"}` → UI prompts for clarification.
- User edits command into something destructive → heuristic re-flags on the edited card.

## 11. Testing

- Unit: destructive heuristic table (known commands), prompt-building fixtures, JSON contract parsing (valid/invalid model output).
- Integration (container): ask → approve → run `du -sh`; verify audit entry; destructive flag on `rm -rf`; save-as-script round trip.
- Manual: streaming UX, provider errors, context chips.

## 12. Acceptance criteria

- [ ] Full ask → approve → run → audit loop works with a real OpenAI-compatible endpoint.
- [ ] Destructive heuristic flags the fixture list; edited commands re-flag.
- [ ] Nothing executes without an explicit Run click (verified by audit log).
- [ ] Keys live only in the Keychain; config JSON has no secrets.
- [ ] Save-as-script produces a working script.
