export interface LogRequestToken {
  generation: number;
  serverId: string;
  path: string | null;
}

export function isCurrentLogRequest(
  token: LogRequestToken,
  generation: number,
  serverId: string,
  path: string | null,
): boolean {
  return token.generation === generation && token.serverId === serverId && token.path === path;
}

// Poll cursors are absolute byte positions owned by the backend. They must
// never be reconstructed from JavaScript string lengths.
export function nextLogCursor(responseCursor: number): number {
  return responseCursor;
}
