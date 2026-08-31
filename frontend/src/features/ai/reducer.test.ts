import { describe, expect, it } from "vitest";
import type { AiEventPoll, AiTurnEvent } from "../../types";
import { aiTurnFeedReducer, initialAiTurnFeed } from "./reducer";

function poll(streamId: string, events: AiTurnEvent[], dropped = 0): AiEventPoll<AiTurnEvent> {
  return { ok: true, stream_id: streamId, cursor: events.at(-1)?.sequence ?? 0, dropped, finished: false, state: "requesting", events };
}

describe("AI turn event reducer", () => {
  it("ignores delayed streams and non-monotonic events", () => {
    const first = aiTurnFeedReducer(initialAiTurnFeed, { type: "poll", poll: poll("turn-a", [
      { version: 1, stream_id: "turn-a", sequence: 2, type: "provider.progress", payload: { phase: "streaming", received_bytes: 48 } },
    ]) });
    const staleSequence = aiTurnFeedReducer(first, { type: "poll", poll: poll("turn-a", [
      { version: 1, stream_id: "turn-a", sequence: 1, type: "turn.started", payload: { state: "queued" } },
    ]) });
    const staleStream = aiTurnFeedReducer(staleSequence, { type: "poll", poll: poll("turn-b", [
      { version: 1, stream_id: "turn-b", sequence: 9, type: "turn.completed", payload: { state: "completed" } },
    ]) });
    expect(staleStream).toEqual(first);
  });

  it("makes cursor gaps visible and applies a typed proposal", () => {
    const proposal = {
      id: "proposal-1", turn_id: "turn-a", revision: 1, server_id: "server-1", provider_id: "provider-1",
      provider_revision: 2, context_hash: "hash", command: "uname -a", command_sha256: "a".repeat(64),
      explanation: "Inspect the kernel.", model_destructive: false, local_destructive: false, needs_sudo: false,
      created_at_ms: 1, expires_at_ms: 2, state: "awaiting_approval" as const,
    };
    const result = aiTurnFeedReducer(initialAiTurnFeed, { type: "poll", poll: poll("turn-a", [
      { version: 1, stream_id: "turn-a", sequence: 3, type: "proposal.ready", payload: { proposal } },
    ], 2) });
    expect(result.dropped).toBe(2);
    expect(result.proposal?.command).toBe("uname -a");
    expect(result.status).toBe("Proposal ready");
  });

  it("restores a durable provider question from a thread snapshot", () => {
    const result = aiTurnFeedReducer(initialAiTurnFeed, {
      type: "snapshot",
      question: "Which service should I inspect?",
      proposal: null,
      status: "completed",
    });
    expect(result.question).toBe("Which service should I inspect?");
    expect(result.status).toBe("completed");
  });

  it("projects a normal assistant message without inventing a tool call", () => {
    const result = aiTurnFeedReducer(initialAiTurnFeed, { type: "poll", poll: poll("turn-a", [
      { version: 1, stream_id: "turn-a", sequence: 4, type: "assistant.message", payload: { message: "The root filesystem is 56% used.", explanation: "Summarized reviewed output." } },
    ]) });
    expect(result.assistantMessage).toBe("The root filesystem is 56% used.");
    expect(result.proposal).toBeNull();
    expect(result.status).toBe("Completed");
  });
});
