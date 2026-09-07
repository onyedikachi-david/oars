import type { AiEventPoll, AiProposal, AiTurnEvent } from "../../types";

export interface AiTurnFeedState {
  streamId: string | null;
  lastSequence: number;
  dropped: number;
  status: string | null;
  assistantMessage: string | null;
  question: string | null;
  proposal: AiProposal | null;
  error: string | null;
}

export const initialAiTurnFeed: AiTurnFeedState = {
  streamId: null,
  lastSequence: -1,
  dropped: 0,
  status: null,
  assistantMessage: null,
  question: null,
  proposal: null,
  error: null,
};

export type AiTurnFeedAction =
  | { type: "reset" }
  | { type: "status"; status: string }
  | { type: "snapshot"; assistantMessage?: string | null; question: string | null; proposal: AiProposal | null; status: string | null }
  | { type: "poll"; poll: AiEventPoll<AiTurnEvent> };

const knownTurnEvents = new Set<AiTurnEvent["type"]>([
  "turn.started", "context.ready", "context.failed", "provider.request_started",
  "provider.response_created", "provider.progress", "proposal.ready", "assistant.message", "question.ready",
  "provider.refusal", "turn.incomplete", "turn.failed", "turn.cancel_requested",
  "turn.canceled", "turn.completed", "turn.approved", "execution.started",
  "execution.output_gap",
]);

export function aiTurnFeedReducer(state: AiTurnFeedState, action: AiTurnFeedAction): AiTurnFeedState {
  if (action.type === "reset") return initialAiTurnFeed;
  if (action.type === "status") return { ...state, status: action.status };
  if (action.type === "snapshot") return { ...initialAiTurnFeed, assistantMessage: action.assistantMessage ?? null, question: action.question, proposal: action.proposal, status: action.status };

  const { poll } = action;
  if (state.streamId !== null && poll.stream_id !== state.streamId) return state;
  let next: AiTurnFeedState = {
    ...state,
    streamId: poll.stream_id,
    dropped: state.dropped + poll.dropped,
    status: poll.dropped > 0
      ? `${poll.dropped} AI status event${poll.dropped === 1 ? " was" : "s were"} dropped. The current snapshot was kept.`
      : state.status,
  };

  for (const candidate of poll.events) {
    // Bridge JSON is untrusted at runtime even though callers use the exact
    // union. Unknown events stop this poll instead of mutating UI state.
    if (!knownTurnEvents.has(candidate.type)) {
      return { ...next, error: "The app received an unsupported AI event. Refresh the conversation before continuing." };
    }
    if (candidate.stream_id !== poll.stream_id || candidate.sequence <= next.lastSequence) continue;
    next = { ...next, lastSequence: candidate.sequence };
    const event = candidate as AiTurnEvent;
    switch (event.type) {
      case "turn.started": next = { ...next, status: event.payload.state }; break;
      case "context.ready": next = { ...next, status: "Context collected" }; break;
      case "context.failed": next = { ...next, error: event.payload.error }; break;
      case "provider.request_started": next = { ...next, status: "Waiting for the provider" }; break;
      case "provider.response_created": next = { ...next, status: "Receiving the provider response" }; break;
      case "provider.progress": next = { ...next, status: event.payload.phase }; break;
      case "proposal.ready": next = { ...next, proposal: event.payload.proposal, question: null, error: null, status: "Proposal ready" }; break;
      case "assistant.message": next = { ...next, assistantMessage: event.payload.message, question: null, proposal: null, error: null, status: "Completed" }; break;
      case "question.ready": next = { ...next, question: event.payload.question, proposal: null, error: null, status: "Provider question" }; break;
      case "provider.refusal": next = { ...next, error: event.payload.reason ?? "The provider refused this request.", status: "Provider refusal" }; break;
      case "turn.incomplete":
      case "turn.failed": next = { ...next, error: event.payload.error, status: event.type === "turn.incomplete" ? "Provider response incomplete" : "Turn failed" }; break;
      case "turn.cancel_requested": next = { ...next, status: "Stop requested" }; break;
      case "turn.canceled": next = { ...next, status: "Canceled" }; break;
      case "turn.completed": next = { ...next, status: "Completed" }; break;
      case "turn.approved": next = { ...next, status: "Approved" }; break;
      case "execution.started": next = { ...next, status: "Command running" }; break;
      case "execution.output_gap": next = { ...next, dropped: next.dropped + event.payload.dropped, status: "Command output has a gap" }; break;
    }
  }
  return next;
}
