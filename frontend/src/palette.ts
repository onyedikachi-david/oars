export type PaletteMode = "action" | "server" | "script" | "history";
export interface SearchableCommand { id: string; title: string; subtitle?: string; category?: string; keywords?: string[]; mode?: PaletteMode; danger?: boolean; }
const prefixes: Record<string, PaletteMode> = { ">": "action", "@": "server", "#": "script", "/": "history" };
export function parsePaletteQuery(query: string) {
  const text = query.trimStart();
  const mode = prefixes[text[0]];
  return { mode, text: (mode ? text.slice(1) : text).trim().toLowerCase() };
}
function score(text: string, query: string) {
  const value = text.toLowerCase();
  if (!query) return 0;
  if (value === query) return 1000;
  if (value.startsWith(query)) return 800 - value.length / 1000;
  const index = value.indexOf(query);
  if (index >= 0) return 600 - index;
  let position = 0; let gaps = 0;
  for (const char of query) {
    const found = value.indexOf(char, position);
    if (found < 0) return -1;
    gaps += found - position; position = found + 1;
  }
  return Math.max(1, 300 - gaps);
}
export function rankCommands<T extends SearchableCommand>(commands: readonly T[], query: string, recentIds: readonly string[] = []): T[] {
  const { mode, text } = parsePaletteQuery(query);
  return commands.filter(command => !mode || (command.mode ?? "action") === mode).map((command, index) => ({ command, index, score: Math.max(score(command.title, text), score([command.subtitle, command.category, ...(command.keywords ?? [])].filter(Boolean).join(" "), text) - 100) })).filter(item => item.score >= 0).sort((a, b) => {
    if (!text) {
      const recentA = recentIds.indexOf(a.command.id); const recentB = recentIds.indexOf(b.command.id);
      if (recentA !== recentB) return (recentA < 0 ? Infinity : recentA) - (recentB < 0 ? Infinity : recentB);
    }
    return b.score - a.score || a.index - b.index;
  }).map(item => item.command);
}
export interface PaletteState { recentIds: string[]; query: string; }
export function readPaletteState(): PaletteState {
  try {
    const value = JSON.parse(localStorage.getItem("oars.palette") ?? "{}");
    return { recentIds: Array.isArray(value.recentIds) ? value.recentIds.filter((id: unknown): id is string => typeof id === "string").slice(0, 5) : [], query: typeof value.query === "string" ? value.query : "" };
  } catch { return { recentIds: [], query: "" }; }
}
export function savePaletteState(state: PaletteState) { try { localStorage.setItem("oars.palette", JSON.stringify(state)); } catch { /* Navigation still works when storage is unavailable. */ } }
