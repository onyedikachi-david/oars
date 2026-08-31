export const AI_PREVIEW_MODES = [
  "no-server",
  "no-provider",
  "credential-missing",
  "context-disclosure",
  "provider-test-running",
  "provider-auth-failed",
  "assistant-message",
  "streaming",
  "question",
  "refusal",
  "proposal-safe",
  "proposal-destructive",
  "proposal-edited",
  "execution-running",
  "cancel-requested",
  "recovery-required",
  "summary-disclosure",
  "long-command",
] as const;

export type AiPreviewMode = typeof AI_PREVIEW_MODES[number];

const AI_PREVIEW_MODE_SET = new Set<string>(AI_PREVIEW_MODES);

export function readAiPreviewMode(): AiPreviewMode | null {
  if (typeof window === "undefined" || document.documentElement.dataset.previewVariant === undefined) return null;
  const requested = new URLSearchParams(window.location.search).get("ai");
  return requested !== null && AI_PREVIEW_MODE_SET.has(requested)
    ? requested as AiPreviewMode
    : null;
}
