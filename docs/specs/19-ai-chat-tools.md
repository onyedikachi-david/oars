# Spec 19 — Conversational AI and reviewed tools

**Status:** Complete. Spec 11 provides the native credential, provider,
conversation, proposal, and tracked-execution foundation. This spec replaces
the workflow-shaped presentation with one chronological chat and adds native
provider tool-call parsing, assistant prose messages, and post-execution
tool-result continuation.

## 1. Overview

AI operations is a conversation about one exact server. A turn can produce
assistant text, ask the operator a question, or propose one reviewed server
command. A command appears inline in the transcript, remains inert until the
operator approves it, streams its tracked output in the same item, and can be
sent back to the provider for a plain-language follow-up.

## 2. Goals and non-goals

### Goals

- Use a familiar message timeline and persistent composer.
- Keep provider setup and context disclosure available without making them the
  primary layout.
- Represent assistant text, questions, command approval, execution, and output
  as typed conversation parts.
- Preserve native authority over credentials, provider HTTP, durable state,
  approval, command classification, and SSH execution.
- Bind every reviewed command to a stable call identity and one frozen target.

### Non-goals

- The model does not execute commands or choose a different server.
- Oars does not run parallel tools in one turn.
- The React WebView does not store provider secrets or call a provider.
- V1 does not expose general web, file, MCP, computer-use, or arbitrary custom
  tools to a provider.

## 3. User stories

1. As an operator, I can ask a server question and read the answer in a normal
   message thread.
2. As an operator, I can see why a command is proposed, inspect or edit the
   exact command, and approve or decline it without leaving the transcript.
3. As an operator, I can watch bounded command output and see its verified exit
   state inside the related tool item.
4. As an operator, I can ask Oars to explain retained output and receive prose,
   not another shell command.
5. As an operator, I can see the exact context that will leave the computer and
   change it before I send a message.
6. As an operator, I can recover a saved conversation after restart without the
   interface inventing missing provider or execution state.

## 4. UI and UX

The transcript is the primary surface. Messages use distinct user and assistant
roles. A reviewed command is an inline tool card with these states: preparing,
awaiting approval, approved, running, completed, failed, canceled, expired, and
recovery required. The card contains the exact target, command, explanation,
destructive warning, approval controls, output, exit status, and follow-up
action when each item becomes relevant.

The composer stays at the bottom of the transcript and names its blocker when
send is unavailable. Context disclosure is summarized immediately above the
composer; a details control opens the full selection. Provider and conversation
controls live in a compact secondary rail or sheet. Empty state prompts insert
text into the composer and never start a request implicitly.

Keyboard rules:

- `Enter` sends a single-line message; `Shift+Enter` adds a line.
- Tool approval always requires an explicit button or focused keyboard action.
- Focus moves to a newly created approval card only when the operator initiated
  the turn and reduced-motion settings allow it.
- Status is expressed with text and an icon, never color alone.

## 5. Bridge API

Spec 11 bridge commands remain authoritative. Their results are projected into
these typed chat parts:

| Native result or event | Chat part |
|---|---|
| queued turn message | `user-text` |
| `assistant.message` | `assistant-text` |
| `question.ready` | `assistant-question` |
| `proposal.ready` | `tool-run-server-command` with `approval-requested` |
| `execution.started` | the same tool part with `running` |
| tracked SSH deltas and EOF | the same tool part with output and terminal state |
| provider or recovery failure | inline `error` part |

New and extended payloads:

- Turn snapshots include `assistant_message`, the frozen `proposal`, execution
  cursor, and verified exit status so completed tool items remain in order.
- `assistant.message` carries `{message, explanation}` and is followed by the
  durable `turn.completed` event.
- A future native provider-tool adapter adds `provider_call_id` and `tool_name`
  to the frozen proposal. It accepts only `run_server_command` and rejects an
  unknown, duplicate, malformed, or parallel call before a proposal is saved.

No bridge result contains credentials, provider authorization headers, or an
unredacted secret.

## 6. Zig core design

`src/ai/proposal.zig` validates a closed result union: `message`, `question`, or
`command`. Message results contain bounded UTF-8 prose. Command results still
pass the local destructive classifier before they can become a frozen proposal.

Provider adapters may implement this union with strict structured output or a
native function tool. A native tool adapter declares one strict
`run_server_command` function, disables parallel tool calls, incrementally
assembles arguments under the existing bounds, and returns a provider-neutral
result to the coordinator. The coordinator never executes from provider wire
data; it first journals the result and freezes a proposal.

After tracked execution, an operator may approve one retained cursor range for
follow-up. The adapter encodes the tool result with its original provider call
identity. If the range has expired or contains a gap, Oars refuses the
continuation and asks the operator to run or select output again.

## 7. Data model and persistence

The journal stores user messages, bounded assistant messages, questions,
provider call identity, continuation items, frozen proposals, approval,
execution admission, terminal state, and selected output cursors. It never
stores credentials or raw authorization headers. Thread snapshots are rebuilt
from the journal; the WebView keeps only a projection.

A frozen command call binds:

- conversation, turn, proposal, and provider call IDs;
- exact server and SSH connection generation;
- provider ID and revision;
- reviewed context hash;
- command and SHA-256;
- model and local destructive classifications;
- creation, expiry, revision, and state.

## 8. Security

The WebView is an untrusted presentation boundary. This is why the release gate
mentions browser state even though Oars uses the Native SDK: React still runs in
a WebView and must never receive a provider or SSH secret.

Provider tools have capability-level allowlists, strict argument schemas, one
call per turn, and no automatic execution. Oars treats user, host, process, log,
command output, and provider text as untrusted data. A command becomes executable
only after native persistence, local validation, target binding, an unexpired
revision check, and explicit operator approval.

## 9. Performance

- Render long transcripts with a bottom-anchored scroller and stable message
  keys; do not replace the full list for one stream delta.
- Keep provider and bridge payloads within Spec 11 bounds.
- Batch visual output updates to the animation frame while retaining exact byte
  cursors in native state.
- Do not block the runtime main thread on provider or SSH I/O.

## 10. Edge cases

- A provider sends text and a tool call in one turn: retain the text and one
  reviewed call in order; reject a second call.
- A provider sends malformed or partial arguments: fail the turn without a
  proposal.
- A proposal expires while visible: replace approval controls with a clear
  expired state.
- The provider, credential, context, connection, or command revision changes:
  reject approval as stale.
- Output has a retention gap: show the gap and do not summarize missing bytes.
- Reviewed context is missing, stale, partial, or reports a probe error: when
  one safe read-only command can collect the requested server facts, propose
  that command instead of asking the operator to supply the data.
- The app restarts during a provider request or execution: show interrupted or
  recovery-required state; never infer success.
- A provider does not support tools: use the closed structured-output union and
  keep the same native chat-part contract.

## 11. Testing

- Unit-test strict message, question, and command validation and every invalid
  discriminator.
- Feed provider SSE one byte at a time for text, tool arguments, malformed
  calls, duplicates, and terminal events.
- Verify provider requests declare one strict tool and disable parallel calls
  where the adapter supports native tools.
- Verify journals recover assistant text and tool state without secrets.
- Verify the provider policy proposes one reviewed read-only diagnostic command
  for unavailable server telemetry and reserves questions for unresolved
  operator intent or target ambiguity.
- Verify the reducer handles duplicate, unknown, dropped, and out-of-order
  events without inventing state.
- Test keyboard send, blocked-send explanation, context review, command edit,
  destructive acknowledgement, approve, cancel, output, and follow-up.
- Run desktop-width and narrow-width visual checks in light and dark themes.

## 12. Acceptance criteria

- [x] A normal server question can end in an assistant prose message.
- [x] A retained-output summary returns prose in the same conversation.
- [x] A proposed command appears as an inline reviewed tool call.
- [x] The model cannot run a command without explicit native approval.
- [x] Execution output and verified exit status remain attached to the tool call.
- [x] Refresh and restart reconstruct the transcript from native state; output
      bytes are reattached only while their tracked SSH channel is retained.
- [x] Provider and context setup are discoverable but secondary to chat.
- [x] The composer explains every disabled state and supports the keyboard rules.
- [x] Missing or failed telemetry leads to a reviewed read-only diagnostic
      command when one command can collect the requested facts.
- [x] Native credential lifecycle passes without exposing a secret in WebView
      state, bridge output, logs, journals, or persisted JSON.
- [x] Provider tool calls pass malformed, duplicate, parallel, and stale-state
      rejection tests.
- [x] Zig, frontend, integration, accessibility, responsive, and dark-theme
      gates pass with recorded evidence.

## 13. Research and references

- OpenAI, “Function calling” and Responses function-call items. Function calls
  carry a `call_id`; applications execute them and return results explicitly:
  <https://platform.openai.com/docs/guides/function-calling>.
- OpenAI, “Streaming API responses.” Responses streaming emits typed output-item
  and function-argument events that must be assembled and validated:
  <https://platform.openai.com/docs/guides/streaming-responses>.
- AI SDK, “Chatbot Tool Usage.” UI message parts use explicit tool lifecycle and
  approval states; Oars adopts the presentation model while keeping transport
  and authority native: <https://ai-sdk.dev/docs/ai-sdk-ui/chatbot-tool-usage>.
- AI SDK, “Transport.” Chat transport is replaceable, which supports a native
  bridge instead of an HTTP `/api/chat` route:
  <https://ai-sdk.dev/docs/ai-sdk-ui/transport>.
- shadcn/ui chatbot template, MIT-licensed reference for the message scroller,
  composer, and inline tool presentation requested for this surface:
  <https://github.com/shadcn-ui/chatbot-template>.
- Local authority: `docs/DESIGN.md`, `docs/specs/11-ai-terminal.md`,
  `src/ai/coordinator.zig`, `src/ai/responses.zig`, `src/ai/chat.zig`, and
  `frontend/src/AiTab.tsx` (reviewed 2026-08-31).

Research correction: Spec 11 deliberately rejected provider tool calls and
allowed only command or question output. That contract cannot produce a normal
assistant answer, so this spec adds an assistant-message result and defines a
separate reviewed tool lifecycle without weakening the native approval boundary.
