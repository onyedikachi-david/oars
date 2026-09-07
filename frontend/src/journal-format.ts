/** Keep unknown event names readable without inventing a successful outcome. */
export function auditTitle(type: string): string {
  const titles: Record<string, string> = {
    "exec": "Command",
    "shell": "Shell command",
    "backup.operation.admitted": "Backup operation started",
    "backup.operation.terminal": "Backup operation finished",
    "ai.turn.summarize": "AI output summary requested",
    "access.scan": "Access scan",
  };
  return titles[type] ?? type.replace(/[._-]+/g, " ").replace(/^\w/, character => character.toUpperCase());
}
export function journalTime(ns: number): string {
  const date = new Date(ns / 1e6);
  return Number.isFinite(date.getTime()) ? date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "Time unavailable";
}
