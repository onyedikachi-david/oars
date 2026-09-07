export type AppShortcut = "palette" | "close" | "new" | "reopen" | "settings" | "files" | "logs" | `tab-${number}`;
export function isMacPlatform() { return /Mac|iPhone|iPad/.test(navigator.platform); }
export function appShortcut(event: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey">, mac: boolean, inTerminal = false): AppShortcut | null {
  const key = event.key.toLowerCase();
  if (/^[1-9]$/.test(key) && !event.shiftKey && (mac ? event.metaKey && !event.ctrlKey && !event.altKey : event.altKey && !event.ctrlKey && !event.metaKey)) return `tab-${key}` as AppShortcut;
  if (event.altKey || (mac ? !event.metaKey || event.ctrlKey : !event.ctrlKey || event.metaKey)) return null;
  if (key === "," && !event.shiftKey) return "settings";
  if (mac) {
    if (key === "t") return event.shiftKey ? "reopen" : "new";
    if (event.shiftKey) return null;
    if (key === "k") return "palette";
    if (key === "w") return "close";
    if (key === "e") return "files";
    if (key === "l" && !inTerminal) return "logs";
  } else if (event.shiftKey) {
    if (key === "p") return "palette";
    if (key === "w") return "close";
    if (key === "t") return "new";
    if (key === "r") return "reopen";
    if (key === "e") return "files";
    if (key === "l" && !inTerminal) return "logs";
  }
  return null;
}
