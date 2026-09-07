import type { CommandItem } from "./components/CommandPalette";
import type { HistoryEntry, Script, Server } from "./types";

/** Declarative navigation registry. Entries open reviewed feature flows. */
export function buildActionRegistry<View extends string>(input: {
  sections: readonly string[]; views: readonly { id: View; label: string }[];
  servers: readonly Server[]; scripts: readonly Script[]; history: readonly HistoryEntry[];
  tabs: readonly { key: string; server: Server; view: View }[];
  navigate: (section: string) => void; openServer: (server: Server) => void;
  openView: (view: View) => void; chooseScriptTarget: (script: Script) => void;
  openGroup: (group: string) => void; reviewHistory: (entry: HistoryEntry) => void;
  activateTab: (key: string) => void; addServer: () => void; appearance: () => void;
  mirror: () => void; closeTab: () => void; clearAudit: () => void;
  data?: () => void;
  theme: string; toggleTheme: () => void;
}): CommandItem[] {
  const names = new Map(input.servers.map(server => [server.id, server.name]));
  const keywords: Record<string, string[]> = { keys: ["ssh", "rotate", "revoke", "deploy key"], logs: ["scan", "tail", "search"], files: ["upload", "download", "sftp"], backups: ["restore", "schedule"], agent: ["identities", "forwarding", "jump"], ai: ["assistant", "proposal", "chat"], vault: ["export", "import", "configuration"], monitor: ["cpu", "memory", "disk", "processes"], deploy: ["deployment", "application", "redeploy"], history: ["replay", "audit"] };
  return [
    ...input.sections.map(section => ({ id: `section:${section}`, title: `Go to ${section}`, category: "Navigation", keywords: section === "Security" ? ["access", "offboard", "people", "roles"] : [], run: () => input.navigate(section) })),
    ...input.views.map(view => ({ id: `view:${view.id}`, title: `Open ${view.label}`, keywords: keywords[view.id] ?? [], category: "Views", run: () => input.openView(view.id) })),
    ...input.servers.map(server => ({ id: `server:${server.id}`, title: server.name, subtitle: `${server.user}@${server.host}:${server.port}`, keywords: [server.group, ...server.tags], mode: "server" as const, category: "Servers", run: () => input.openServer(server) })),
    ...input.scripts.map(script => ({ id: `script:${script.id}`, title: `Run “${script.name}”…`, keywords: script.tags, mode: "script" as const, category: "Scripts", subtitle: "Choose a server and review before running", run: () => input.chooseScriptTarget(script) })),
    ...Array.from(new Set(input.servers.map(server => server.group))).map(group => ({ id: `group:${group}`, title: `Open group ${group || "Ungrouped"}`, category: "Groups", run: () => input.openGroup(group) })),
    ...input.history.map(entry => ({ id: `history:${entry.id}`, title: entry.command, subtitle: `${names.get(entry.server_id) ?? entry.server_id} · ${entry.redacted ? "redacted; replay unavailable" : "review replay"}`, mode: "history" as const, category: "History", run: () => input.reviewHistory(entry) })),
    ...input.tabs.map((tab, index) => ({ id: `tab:${tab.key}`, title: `Tab ${index + 1}: ${tab.server.name} · ${tab.view}`, category: "Tabs", run: () => input.activateTab(tab.key) })),
    { id: "server:add", title: "Add server…", category: "Actions", run: input.addServer },
    { id: "tab:mirror", title: "New mirrored terminal", category: "Tabs", run: input.mirror },
    { id: "tab:close", title: "Close current tab", category: "Tabs", run: input.closeTab },
    { id: "audit:clear", title: "Clear audit journal…", category: "Actions", danger: true, run: input.clearAudit },
    ...(input.data ? [{ id: "settings:data", title: "Open data transfer", category: "Settings", keywords: ["vault", "export", "import", "configuration"], run: input.data }] : []),
    { id: "settings:appearance", title: "Appearance settings", category: "Settings", run: input.appearance },
    { id: "theme:toggle", title: `Theme: switch to ${input.theme === "dark" ? "light" : "dark"}`, category: "Settings", run: input.toggleTheme },
  ];
}
