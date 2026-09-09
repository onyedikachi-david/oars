import { WorkspacePages } from "./components/WorkspacePages";
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Archive,
  ArrowUpRight,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Settings,
  Cloud,
  Command,
  HardDrive,
  GripVertical,
  Maximize2,
  Minimize2,
  KeyRound,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  ListChecks,
  LockKeyhole,
  Menu,
  Moon,
  MoreHorizontal,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Sun,
  Terminal,
  UserRound,
  X,
  Zap,
} from "lucide-react";
import { MosaicWindow, type MosaicNode, type MosaicPath } from "react-mosaic-component";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { WorkspaceLayoutPicker } from "./components/WorkspaceLayoutPicker";
import { WorkspacePaneMenu } from "./components/WorkspacePaneMenu";
import { WorkspacePaneSlot, WorkspaceSurfaces } from "./components/WorkspaceSurfaces";
import { WorkspaceDockTabContext } from "./components/WorkspaceDockTab";
import { WorkspaceDocking, WorkspaceDragHandle } from "./components/WorkspaceDocking";
import { ApplicationNotice } from "./components/ApplicationPortal";
import { api, BridgeError } from "./bridge";
import type { Server as OarsServer, SessionStatus, Script, ScriptDraft, DeployApp } from "./types";
import { TerminalTab } from "./TerminalTab";
import { ServerModal } from "./ServerModal";
import { MonitorTab } from "./MonitorTab";
import { LogsTab } from "./LogsTab";
import { FilesTab } from "./FilesTab";
import { ScriptsTab } from "./ScriptsTab";
import { DataSettings } from "./components/DataSettings";
import { buildActionRegistry } from "./actions";
import { PaletteTargetDialog } from "./components/PaletteTargetDialog";
import { parsePaletteQuery } from "./palette";
import { FleetList } from "./components/FleetList";
import { GroupView } from "./components/GroupView";
import { GroupEditDialog } from "./components/GroupEditDialog";
import { groupMembers, moveGroupProfiles } from "./fleet";
import { useFleetMove } from "./useFleetMove";
import { useAppearance, updateAppearance } from "./appearance";
import { appShortcut, isMacPlatform } from "./keyboard";
import { readPaletteState } from "./palette";
import type { HistoryEntry } from "./types";
import { ConnectionStatus } from "./components/ConnectionStatus";
import { auditTitle, journalTime } from "./journal-format";
import { AppearanceSettings } from "./components/AppearanceSettings";
import { CommandPalette, type CommandItem } from "./components/CommandPalette";
import { DeployTab } from "./DeployTab";
import { KeysTab } from "./KeysTab";
import { AccessTab } from "./AccessTab";
import { BackupsTab } from "./BackupsTab";
import { readBackupPreviewMode } from "./backup-preview";
import { readAiPreviewMode } from "./ai-preview";
import { AiTab } from "./AiTab";
import { HistoryTab } from "./HistoryTab";
import { AgentTab } from "./AgentTab";
import {
  MAX_WORKSPACE_PANES,
  buildWorkspaceLayout,
  reconcileWorkspaceLayout,
  activateWorkspacePane,
  dockWorkspacePane,
  workspaceLayoutKeys,
  type WorkspaceLayoutVariant,
} from "./workspace-layout";

const VncTab = lazy(() => import("./VncTab").then((module) => ({ default: module.VncTab })));

// ---------------------------------------------------------------------------
// Shell nav
// ---------------------------------------------------------------------------
type Section = "Overview" | "Servers" | "Activity" | "Automation" | "Security" | "Backups" | "AI Context";
type View = "monitor" | "terminal" | "logs" | "files" | "scripts" | "deploy" | "keys" | "backups" | "ai" | "vnc" | "history" | "agent";

interface Tab {
  server: OarsServer;
  key: string;
  view: View;
}

const VIEWS: { id: View; label: string }[] = [
  { id: "monitor", label: "Monitor" },
  { id: "terminal", label: "Terminal" },
  { id: "logs", label: "Logs" },
  { id: "files", label: "Files" },
  { id: "scripts", label: "Scripts" },
  { id: "deploy", label: "Deploy" },
  { id: "keys", label: "Keys" },
  { id: "backups", label: "Backups" },
  { id: "ai", label: "AI" },
  { id: "vnc", label: "VNC" },
  { id: "history", label: "History" },
  { id: "agent", label: "Agent" },
];

const CONNECTION_VIEWS = new Set<View>(["monitor", "logs", "files", "deploy", "keys", "backups", "ai", "vnc"]);

const navGroups = [
  { label: "Workspace", items: [{ label: "Overview", icon: LayoutDashboard }, { label: "Servers", icon: Server }, { label: "Activity", icon: Activity }] },
  { label: "Operations", items: [{ label: "Automation", icon: Zap }, { label: "Security", icon: ShieldCheck }, { label: "Backups", icon: Archive }] },
  { label: "Intelligence", items: [{ label: "AI Context", icon: Bot }] },
] as const;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function fleetLabel(s?: SessionStatus): string {
  if (!s || s === "closed") return "Offline";
  if (s === "ready") return "Connected";
  if (s === "needs_trust") return "Needs attention";
  if (s === "error") return "Failed";
  return "Connecting";
}
function initials(name: string) {
  const parts = name.split(/[-_\s]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}
function SectionTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return (
    <div className="section-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="section-description">{description}</p>
      </div>
      {action}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview (fleet) — wired to real servers + statuses
// ---------------------------------------------------------------------------
function Overview({
  servers,
  statuses,
  search,
  onAdd,
  onOpenServer,
  onAction,
}: {
  servers: OarsServer[];
  statuses: Map<string, SessionStatus>;
  search: string;
  onAdd: () => void;
  onOpenServer: (s: OarsServer) => void;
  onAction: (label: string) => void;
}) {
  const filtered = useMemo(() => {
    if (!search) return servers;
    const q = search.toLowerCase();
    return servers.filter((s) => `${s.name} ${s.host} ${s.group ?? ""}`.toLowerCase().includes(q));
  }, [servers, search]);

  const online = servers.filter((s) => statuses.get(s.id) === "ready").length;
  const total = servers.length;

  // recent activity from bridge
  const [activities, setActivities] = useState<{ title: string; detail: string; time: string; icon: any; tone: string }[]>([]);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r: any = await api.history.auditList();
        const entries: any[] = r.entries ?? r.audit ?? r ?? [];
        if (cancelled) return;
        if (entries.length > 0) {
          const mapped = entries.slice(0, 5).map((e: any) => ({
            title: auditTitle(e.action ?? e.type ?? "Activity"),
            detail: e.target || e.server_id || e.result || "Local workspace",
            time: journalTime(e.ts),
            icon: Terminal,
            tone: "info",
          }));
          setActivities(mapped);
        }
      } catch {
        // leave defaults
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const displayActivities = activities.length > 0 ? activities : [
    { title: "No recent activity", detail: "Audit entries will appear here", time: "", icon: Terminal, tone: "muted" },
  ];

  return (
    <div className="content-stack">
      <SectionTitle
        eyebrow="Fleet overview"
        title="Overview"
        description={total === 0 ? "No servers yet. Add one to get started." : `${online} of ${total} connection profiles are connected.`}
        action={
          <Button onClick={onAdd}>
            <Plus data-icon="inline-start" /> Add server
          </Button>
        }
      />

      <div className="fleet-summary" aria-label="Fleet summary">
        <span><ConnectionStatus status="ready" /><strong>{online}</strong> connected</span>
        <span><ConnectionStatus status="closed" /><strong>{servers.filter(server => !statuses.get(server.id) || statuses.get(server.id) === "closed").length}</strong> offline</span>
        <span><ConnectionStatus status="error" /><strong>{servers.filter(server => statuses.get(server.id) === "error").length}</strong> failed</span>
        <span><Server size={15} aria-hidden /><strong>{total}</strong> profiles</span>
      </div>

      <div className="overview-grid">
        <div className="panel servers-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Live inventory</p>
              <h2>Servers</h2>
            </div>
            <Button variant="ghost" size="sm" onClick={() => onAction("View all servers")}>
              View all <ArrowUpRight data-icon="inline-end" />
            </Button>
          </div>
          {filtered.length === 0 ? (
            <div style={{ padding: "24px 22px", color: "var(--muted-foreground)", fontSize: 12.5 }}>
              {servers.length === 0 ? "No servers yet. Add your first one — Oars connects over standard SSH, no agent required." : "No servers match your search."}
              <div style={{ marginTop: 12 }}>
                <Button size="sm" onClick={onAdd}>Add server</Button>
              </div>
            </div>
          ) : (
            <LiveServerTable servers={filtered.slice(0, 5)} statuses={statuses} onOpen={onOpenServer} />
          )}
        </div>

        <div className="panel activity-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Audit stream</p>
              <h2>Recent activity</h2>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="More activity" onClick={() => onAction("Activity")}>
              <MoreHorizontal />
            </Button>
          </div>
          <div className={`activity-list activity-compact`}>
            {displayActivities.map((item, i) => (
              <div className="activity-item" key={i}>
                <div className={`activity-icon activity-${item.tone}`}>
                  <item.icon />
                </div>
                <div className="activity-copy">
                  <strong>{item.title}</strong>
                  <span>{item.detail}</span>
                </div>
                <time>{item.time}</time>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="quick-actions">
        <div>
          <p className="eyebrow">Quick actions</p>
          <h2>Workspace actions</h2>
        </div>
        <div className="action-row">
          {[
            { label: "Open shell", icon: Terminal },
            { label: "Run a script", icon: ListChecks },
            { label: "Refresh profiles", icon: RefreshCw },
          ].map((action) => (
            <Button key={action.label} variant="outline" onClick={() => onAction(action.label)}>
              <action.icon data-icon="inline-start" />
              {action.label}
              <ChevronRight data-icon="inline-end" />
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}

function LiveServerTable({
  servers,
  statuses,
  onOpen,
}: {
  servers: OarsServer[];
  statuses: Map<string, SessionStatus>;
  onOpen: (s: OarsServer) => void;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Server</th>
            <th>Status</th>
            <th>Endpoint</th>
            <th>Group</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {servers.map((s) => {
            const st = statuses.get(s.id);
            return (
              <tr key={s.id}>
                <td>
                  <div className="server-cell">
                    <span className="server-avatar">{initials(s.name)}</span>
                    <div>
                      <strong>{s.name}</strong>
                      <span>
                        {s.host}:{s.port} · {s.user}
                      </span>
                    </div>
                  </div>
                </td>
                <td>
                  <span className="status-label">
                    <ConnectionStatus status={st} />
                    {fleetLabel(st)}
                  </span>
                </td>
                <td>
                  <span className="technical-meta">{s.user}@{s.host}:{s.port}</span>
                </td>
                <td>
                  <span className="latency">{s.group || "Ungrouped"}</span>
                </td>
                <td>
                  <Button variant="ghost" size="icon-xs" aria-label={`Open ${s.name}`} onClick={() => onOpen(s)}>
                    <ArrowUpRight />
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-section real views
// ---------------------------------------------------------------------------
function ServersView({
  servers,
  statuses,
  search,
  onOpen,
  onEdit,
  onAdd,
}: {
  servers: OarsServer[];
  statuses: Map<string, SessionStatus>;
  search: string;
  onOpen: (s: OarsServer) => void;
  onEdit: (s: OarsServer) => void;
  onAdd: () => void;
}) {
  const filtered = servers.filter((s) => !search || `${s.name} ${s.host} ${s.group ?? ""}`.toLowerCase().includes(search.toLowerCase()));
  const groups = (() => {
    const m = new Map<string, OarsServer[]>();
    for (const s of filtered) {
      const g = s.group?.trim() || "Ungrouped";
      const arr = m.get(g) ?? [];
      arr.push(s);
      m.set(g, arr);
    }
    return Array.from(m.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  })();

  return (
    <div className="content-stack">
      <SectionTitle
        eyebrow="Fleet & connectivity"
        title="Servers"
        description="Connection profiles, access methods, and host trust at a glance."
        action={
          <Button onClick={onAdd}>
            <Plus data-icon="inline-start" /> Add server
          </Button>
        }
      />
      {filtered.length === 0 ? (
        <div className="panel" style={{ padding: 22 }}>
          <div className="empty-state" style={{ padding: 24 }}>
            <div className="empty-icon"><Server /></div>
            <h3>No servers match</h3>
            <p>Add a server or clear the search filter.</p>
            <Button variant="secondary" onClick={onAdd}>Add server</Button>
          </div>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 14 }}>
          {groups.map(([g, list]) => (
            <div key={g} className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">{g}</p>
                  <h2>{list.length} server{list.length === 1 ? "" : "s"}</h2>
                </div>
                <span className="pill">{g}</span>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Server</th><th>User</th><th>Auth</th><th>Status</th><th /></tr></thead>
                  <tbody>
                    {list.map((s) => {
                      const st = statuses.get(s.id);
                      return (
                        <tr key={s.id}>
                          <td><div className="server-cell"><span className="server-avatar">{initials(s.name)}</span><div><strong>{s.name}</strong><span>{s.host}:{s.port}</span></div></div></td>
                          <td style={{ color: "var(--muted-foreground)", fontSize: 11 }}>{s.user}</td>
                          <td><span className="pill" style={{ textTransform: "capitalize" }}>{s.auth_method}</span></td>
                          <td><span className="status-label"><ConnectionStatus status={st} />{fleetLabel(st)}</span></td>
                          <td style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                            <Button variant="outline" size="sm" onClick={() => onOpen(s)}>Open <ArrowUpRight data-icon="inline-end" /></Button>
                            <Button variant="ghost" size="sm" onClick={() => onEdit(s)}>Edit</Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------
export default function App() {
  const [backupPreviewMode] = useState(readBackupPreviewMode);
  const [aiPreviewMode] = useState(readAiPreviewMode);
  const [servers, setServers] = useState<OarsServer[]>([]);
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Map<string, SessionStatus>>(new Map());
  const [modal, setModal] = useState<{ server?: OarsServer } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQ, setPaletteQ] = useState(() => readPaletteState().query);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [dataOpen, setDataOpen] = useState(false);
  const closedTabs = useRef<Tab[]>([]);
  const [historyForPalette, setHistoryForPalette] = useState<HistoryEntry[]>([]);
  const [historyAction, setHistoryAction] = useState<"clear-audit" | null>(null);
  const [paletteTarget, setPaletteTarget] = useState<{ title: string; view: View; scriptId?: string; mirror?: boolean } | null>(null);
  const [pendingHistory, setPendingHistory] = useState<HistoryEntry | null>(null);
  const appearance = useAppearance();
  const theme = appearance.theme;
  const setTheme = useCallback((next: string) => { updateAppearance({ theme: next === "dark" ? "dark" : "light" }); }, []);
  const [search, setSearch] = useState("");
  const [fleetFilter, setFleetFilter] = useState("");
  const fleetCountRef = useRef(0);
  const [collapsedFleetGroups, setCollapsedFleetGroups] = useState<Set<string>>(() => {
    try { const value: unknown = JSON.parse(localStorage.getItem("oars:fleet-collapsed") ?? "[]"); return new Set(Array.isArray(value) ? value.filter((key): key is string => typeof key === "string") : []); } catch { return new Set(); }
  });
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [moveServer, setMoveServer] = useState<OarsServer | null>(null);
  const [broadcastGroupIds, setBroadcastGroupIds] = useState<string[] | undefined>();
  useEffect(() => { try { localStorage.setItem("oars:fleet-collapsed", JSON.stringify([...collapsedFleetGroups])); } catch {} }, [collapsedFleetGroups]);
  const [serverMenuId, setServerMenuId] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<Section>(() => aiPreviewMode !== null ? "AI Context" : backupPreviewMode === null ? "Overview" : "Backups");
  const [mobileNav, setMobileNav] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem("oars:sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const [defaultLayoutVariant, setDefaultLayoutVariant] = useState<WorkspaceLayoutVariant>(() => {
    try {
      const stored = localStorage.getItem("oars:workspace-layout-default");
      return stored === "columns" || stored === "focus" ? stored : "balanced";
    } catch {
      return "balanced";
    }
  });
  const [layoutVariant, setLayoutVariant] = useState<WorkspaceLayoutVariant>(defaultLayoutVariant);
  const [paneFocused, setPaneFocused] = useState(false);
  const [workspaceNavigationRevision, setWorkspaceNavigationRevision] = useState(0);
  const customLayoutRef = useRef(false);
  const [workspaceMessage, setWorkspaceMessage] = useState("");
  const [mosaicLayout, setMosaicLayout] = useState<MosaicNode<string> | null>(null);
  const [compactWorkspace, setCompactWorkspace] = useState(() => window.matchMedia("(max-width: 900px)").matches);
  const [toast, setToast] = useState("");
  const [serversLoading, setServersLoading] = useState(true);
  const [serversRefreshing, setServersRefreshing] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const fleetSearchRef = useRef<HTMLInputElement>(null);
  const serversLoadedRef = useRef(false);

  const refreshServers = useCallback(async () => {
    const firstLoad = !serversLoadedRef.current;
    if (firstLoad) setServersLoading(true);
    else setServersRefreshing(true);
    try {
      const r = await api.servers.list();
      setServers(r.servers);
      setLoadError(r.recovery_error ?? null);
    } catch (e) {
      setLoadError(e instanceof BridgeError ? e.message : String(e));
    } finally {
      serversLoadedRef.current = true;
      setServersLoading(false);
      setServersRefreshing(false);
    }
  }, []);

  useEffect(() => { refreshServers(); }, [refreshServers]);
  // v0 theming is class-based (.dark / .light) on <html> — keep exactly in sync with index.html boot script
  const applyTheme = useCallback((next: string) => {
    const html = document.documentElement;
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const startTransition = () => {
      if (prefersReduced) return () => {};
      html.classList.add("theme-transition");
      return () => window.setTimeout(() => html.classList.remove("theme-transition"), 260);
    };

    // Prefer View Transitions API when available for a non-jerky cross-fade
    const doSwap = () => {
      html.classList.remove("light", "dark");
      html.classList.add(next);
      // keep layout.tsx's viewport color-scheme in sync; media query :root:not(.light) also depends on this
      html.style.colorScheme = next;
      try { localStorage.setItem("oars:theme", next); } catch {}
      // Keep index.html theme-color meta in sync for PWA chrome
      try {
        const m = document.querySelector('meta[name="theme-color"][media*="light"]') as HTMLMetaElement | null;
        if (m) m.content = next === "dark" ? "#332f29" : "#f4f1e8";
      } catch {}

    };

    const cleanup = startTransition();
    const vt = (document as unknown as { startViewTransition?: (cb: () => void) => { finished: Promise<void> } }).startViewTransition;
    if (vt && !prefersReduced) {
      try {
        // Strict Mode can start the same theme transition twice. The
        // browser aborts the first transition; consume that expected
        // rejection so it does not become a console error.
        void vt.call(document, doSwap).finished.then(cleanup, cleanup);
      } catch {
        doSwap();
        cleanup();
      }
    } else {
      doSwap();
      cleanup();
    }
  }, []);

  useEffect(() => { applyTheme(theme); }, [theme, applyTheme]);
  useEffect(() => { document.documentElement.dataset.accent = appearance.accent; }, [appearance.accent]);

  useEffect(() => {
    try { localStorage.setItem("oars:sidebar-collapsed", String(sidebarCollapsed)); } catch {}
  }, [sidebarCollapsed]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const update = () => setCompactWorkspace(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const tabKeySignature = tabs.map((tab) => tab.key).join("\u0000");
  useEffect(() => {
    const keys = tabKeySignature ? tabKeySignature.split("\u0000") : [];
    if (keys.length === 0) customLayoutRef.current = false;
    setMosaicLayout((current) => customLayoutRef.current
      ? reconcileWorkspaceLayout(current, keys, layoutVariant)
      : buildWorkspaceLayout(keys, layoutVariant));
  }, [tabKeySignature, layoutVariant]);

  useEffect(() => {
    if (activeKey) setMosaicLayout((current) => activateWorkspacePane(current, activeKey));
  }, [activeKey, tabKeySignature, layoutVariant]);

  const setStatus = useCallback((serverId: string, status: SessionStatus) => {
    setStatuses((prev) => {
      const next = new Map(prev);
      next.set(serverId, status);
      return next;
    });
  }, []);

  const [pendingScriptId, setPendingScriptId] = useState<string | null>(null);
  const [pendingScriptDraft, setPendingScriptDraft] = useState<{ tabKey: string; draft: ScriptDraft } | null>(null);
  const [scriptsForPalette, setScriptsForPalette] = useState<Script[]>([]);
  useEffect(() => {
    api.scripts.list().then((r) => setScriptsForPalette(r.scripts)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!paletteOpen) return;
    let active = true;
    api.history.list({ limit: 500 }).then(result => { if (active) setHistoryForPalette(result.entries); }).catch(() => { if (active) setHistoryForPalette([]); });
    api.scripts.list().then(result => { if (active) setScriptsForPalette(result.scripts); }).catch(() => {});
    return () => { active = false; };
  }, [paletteOpen]);

  useEffect(() => {
    if (!paletteOpen) return;
    const parsed = parsePaletteQuery(paletteQ);
    if (parsed.mode !== "history") return;
    let active = true;
    const timer = setTimeout(() => { api.history.list({ limit: 500, q: parsed.text }).then(result => { if (active) setHistoryForPalette(result.entries); }).catch(() => { if (active) setHistoryForPalette([]); }); }, 150);
    return () => { active = false; clearTimeout(timer); };
  }, [paletteOpen, paletteQ]);

  const [pendingDeployApp, setPendingDeployApp] = useState<{ serverId: string; appId: string } | null>(null);
  const [deployAppsForPalette, setDeployAppsForPalette] = useState<Array<{ id: string; name: string; serverId: string }>>([]);

  const handleDeployAppsLoaded = useCallback((serverId: string, apps: DeployApp[]) => {
    setDeployAppsForPalette((prev) => [
      ...prev.filter((a) => a.serverId !== serverId),
      ...apps.map((a) => ({ id: a.id, name: a.name, serverId })),
    ]);
  }, []);

  const showPaneLimit = useCallback(() => {
    setToast(`A workspace can keep up to ${MAX_WORKSPACE_PANES} server views open. Close a view before opening another.`);
    window.setTimeout(() => setToast(""), 2800);
  }, []);

  const openServer = useCallback((server: OarsServer) => {
    setTabs((prev) => {
      const existing = prev.find((t) => t.server.id === server.id);
      if (existing) {
        setActiveKey(existing.key);
        return prev;
      }
      if (prev.length >= MAX_WORKSPACE_PANES) {
        showPaneLimit();
        return prev;
      }
      const tab: Tab = { server, key: server.id, view: "terminal" };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, [showPaneLimit]);

  const openServerView = useCallback((server: OarsServer, view: View) => {
    setTabs((prev) => {
      const existing = prev.find((t) => t.server.id === server.id);
      if (existing) {
        setActiveKey(existing.key);
        return prev.map((tab) => tab.key === existing.key ? { ...tab, view } : tab);
      }
      if (prev.length >= MAX_WORKSPACE_PANES) {
        showPaneLimit();
        return prev;
      }
      const tab: Tab = { server, key: server.id, view };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, [showPaneLimit]);

  const aiPreviewOpened = useRef(false);
  useEffect(() => {
    if (aiPreviewMode === null || aiPreviewOpened.current || serversLoading || servers.length === 0) return;
    aiPreviewOpened.current = true;
    openServerView(servers[0], "ai");
  }, [aiPreviewMode, openServerView, servers, serversLoading]);

  const openMirrored = useCallback((server: OarsServer, view: View = "terminal") => {
    setTabs((prev) => {
      if (prev.length >= MAX_WORKSPACE_PANES) {
        showPaneLimit();
        return prev;
      }
      fleetCountRef.current += 1;
      const tab: Tab = { server, key: `${server.id}#${fleetCountRef.current}`, view };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, [showPaneLimit]);

  const setViewForKey = useCallback((key: string, view: View) => {
    setTabs((prev) => prev.map((tab) => (tab.key === key ? { ...tab, view } : tab)));
    setActiveKey(key);
  }, []);

  const setView = useCallback((view: View) => {
    if (activeKey) setViewForKey(activeKey, view);
  }, [activeKey, setViewForKey]);

  const closeTab = useCallback((key: string) => {
    const tab = tabs.find((item) => item.key === key);
    if (tab) closedTabs.current = [tab, ...closedTabs.current].slice(0, 10);
    const hasAnotherView = tab ? tabs.some((item) => item.key !== key && item.server.id === tab.server.id) : false;
    setTabs((prev) => prev.filter((item) => item.key !== key));
    setActiveKey((active) => {
      if (active !== key) return active;
      const remaining = tabs.filter((item) => item.key !== key);
      return remaining[remaining.length - 1]?.key ?? null;
    });
    if (tab && !hasAnotherView) api.ssh.disconnect(tab.server.id).catch(() => {});
  }, [tabs]);

  const handleSaved = useCallback((saved: OarsServer) => {
    setModal(null);
    refreshServers();
    setTabs((prev) => prev.map((t) => (t.server.id === saved.id ? { ...t, server: saved } : t)));
    openServer(saved);
  }, [refreshServers, openServer]);

  const handleServerUpdated = useCallback((saved: OarsServer) => {
    setServers((current) => current.map((server) => server.id === saved.id ? saved : server));
    setTabs((current) => current.map((tab) => tab.server.id === saved.id ? { ...tab, server: saved } : tab));
  }, []);

  const updateGroupServers = useCallback((updated: OarsServer[]) => {
    const changes = new Map(updated.map(server => [server.id, server]));
    setServers(previous => previous.map(server => changes.get(server.id) ?? server));
    setTabs(previous => previous.map(tab => ({ ...tab, server: changes.get(tab.server.id) ?? tab.server })));
  }, []);
  const fleetMove = useFleetMove((server, group) => {
    void moveGroupProfiles([server], group).then(result => {
      updateGroupServers(result.updated);
      setToast(result.failures.length ? result.failures.map(failure => failure.message).join("; ") : `${server.name} moved to ${group || "Ungrouped"}.`);
    }).catch(error => setToast(String(error)));
  });
  const openGroup = (group: string) => { setActiveGroup(group); setActiveKey(null); setActiveSection("Servers"); };

  const handleDeleted = useCallback((id: string, warning?: string) => {
    // Close all tabs for the removed profile and disconnect the session.
    setTabs((prev) => {
      const remaining = prev.filter((t) => t.server.id !== id);
      setActiveKey((active) => {
        if (!active) return null;
        const stillThere = remaining.some((r) => r.key === active);
        return stillThere ? active : (remaining[remaining.length - 1]?.key ?? null);
      });
      return remaining;
    });
    setStatuses((prev) => {
      const next = new Map(prev);
      next.delete(id);
      return next;
    });
    refreshServers();
    setToast(warning ?? "Connection profile removed.");
    setTimeout(() => setToast(""), warning ? 5000 : 2200);
  }, [refreshServers]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const element = document.activeElement as HTMLElement | null;
      const inTerminal = !!element?.closest(".terminal-host");
      const shortcut = appShortcut(e, isMacPlatform(), inTerminal);
      const overlay = document.querySelector('[role="dialog"][aria-modal="true"]');
      if (overlay) {
        if (paletteOpen && shortcut === "palette") { e.preventDefault(); setPaletteOpen(false); }
        return;
      }
      if (shortcut) {
        e.preventDefault();
        const active = tabs.find(tab => tab.key === activeKey);
        if (shortcut === "palette") setPaletteOpen(true);
        else if (shortcut === "settings") setSettingsOpen(true);
        else if (shortcut === "new") { if (active) openMirrored(active.server); else setModal({}); }
        else if (shortcut === "close" && activeKey) closeTab(activeKey);
        else if (shortcut === "reopen") {
          if (tabs.length >= MAX_WORKSPACE_PANES) { showPaneLimit(); return; }
          const closed = closedTabs.current.shift();
          const server = servers.find(item => item.id === closed?.server.id);
          if (closed && server) openMirrored(server, closed.view);
        } else if (shortcut === "files" && active) setViewForKey(active.key, "files");
        else if (shortcut === "logs" && active) {
          setViewForKey(active.key, "logs");
          requestAnimationFrame(() => document.querySelector<HTMLInputElement>('.logs-search input')?.focus());
        } else if (shortcut.startsWith("tab-")) {
          const tab = tabs[Number(shortcut.slice(4)) - 1];
          if (tab) setActiveKey(tab.key);
        }
        return;
      }
      const inField = element?.matches("input, textarea, select") || element?.isContentEditable;
      if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey && !inField && element?.closest(".sidebar")) {
        e.preventDefault(); fleetSearchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", h, true);
    return () => window.removeEventListener("keydown", h, true);
  }, [paletteOpen, tabs, activeKey, openMirrored, closeTab, servers, setViewForKey, showPaneLimit]);

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null;
  const fleetGroups = useMemo(() => {
    const query = fleetFilter.trim().toLowerCase();
    const filtered = !query
      ? servers
      : servers.filter((server) => `${server.name} ${server.host} ${server.group ?? ""} ${(server.tags ?? []).join(" ")}`.toLowerCase().includes(query));
    const grouped = new Map<string, OarsServer[]>();
    for (const server of filtered) {
      const group = server.group?.trim() || "";
      grouped.set(group, [...(grouped.get(group) ?? []), server]);
    }
    return Array.from(grouped.entries())
      .sort(([a], [b]) => {
        if (!a) return 1;
        if (!b) return -1;
        return a.localeCompare(b);
      })
      .map(([group, entries]) => ({
        key: group || "__ungrouped__",
        path: group,
        label: group || "Ungrouped",
        entries: entries.sort((a, b) => a.name.localeCompare(b.name)),
      }));
  }, [servers, fleetFilter]);

  useEffect(() => {
    if (!serverMenuId) return;
    const closeMenu = (event: PointerEvent) => {
      if (!(event.target as HTMLElement | null)?.closest("[data-server-menu]")) setServerMenuId(null);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setServerMenuId(null);
    };
    window.addEventListener("pointerdown", closeMenu);
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      window.removeEventListener("pointerdown", closeMenu);
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [serverMenuId]);

  const toggleFleetGroup = useCallback((group: string) => {
    setCollapsedFleetGroups((current) => {
      const next = new Set(current);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  }, []);

  const applyLayoutVariant = useCallback((variant: WorkspaceLayoutVariant) => {
    customLayoutRef.current = false;
    setPaneFocused(false);
    setLayoutVariant(variant);
    setMosaicLayout((current) => {
      const currentKeys = workspaceLayoutKeys(current);
      const keys = currentKeys.length > 0 ? currentKeys : tabs.map((tab) => tab.key);
      return buildWorkspaceLayout(keys, variant);
    });
  }, [compactWorkspace, tabs]);

  const saveDefaultLayout = useCallback(() => {
    setDefaultLayoutVariant(layoutVariant);
    try { localStorage.setItem("oars:workspace-layout-default", layoutVariant); } catch {}
    setToast(`${layoutVariant[0].toUpperCase()}${layoutVariant.slice(1)} is now the default layout.`);
    window.setTimeout(() => setToast(""), 2400);
  }, [layoutVariant]);

  function onAction(label: string) {
    // fleet-level quick actions map to real UX
    if (label === "Open shell") {
      if (activeTab) setView("terminal");
      else if (servers[0]) openServer(servers[0]);
      else setToast("Add a server first to open a shell.");
    } else if (label === "Run a script") {
      if (activeTab) setView("scripts");
      else if (servers[0]) openServerView(servers[0], "scripts");
      else setToast("Add a server first to run scripts.");
    } else if (label === "Refresh profiles" || label === "Fleet refresh") {
      refreshServers();
      setToast("Fleet refreshed.");
      setTimeout(() => setToast(""), 2500);
      return;
    } else if (label === "View all servers") {
      setActiveSection("Servers");
      setActiveKey(null);
    } else if (label === "Activity") {
      setActiveSection("Activity");
      setActiveKey(null);
    } else {
      setToast(`${label} — available in the server workspace.`);
    }
    if (label !== "Fleet refresh" && label !== "Refresh profiles") {
      setToast((t) => t || `${label} — opened.`);
      setTimeout(() => setToast(""), 2600);
    } else {
      setTimeout(() => setToast(""), 2200);
    }
  }

  const paletteItems: CommandItem[] = buildActionRegistry({
    sections: navGroups.flatMap(group => group.items.map(item => item.label)), views: VIEWS,
    servers, scripts: scriptsForPalette, history: historyForPalette, tabs,
    navigate: section => { setActiveSection(section as Section); setActiveGroup(null); setBroadcastGroupIds(undefined); setActiveKey(null); },
    openServer,
    openView: view => { if (activeTab) openServerView(activeTab.server, view); else setPaletteTarget({ title: `Open ${view}`, view }); },
    chooseScriptTarget: script => setPaletteTarget({ title: `Run “${script.name}”`, scriptId: script.id, view: "scripts" }),
    openGroup,
    reviewHistory: entry => { setPendingHistory(entry); setActiveSection("Activity"); setActiveKey(null); },
    data: () => setDataOpen(true),
    activateTab: setActiveKey, addServer: () => setModal({}), appearance: () => setSettingsOpen(true),
    mirror: () => { if (activeTab) openMirrored(activeTab.server); else setPaletteTarget({ title: "New mirrored terminal", view: "terminal", mirror: true }); },
    closeTab: () => { if (activeKey) closeTab(activeKey); },
    clearAudit: () => { setHistoryAction("clear-audit"); setActiveSection("Activity"); setActiveKey(null); },
    theme, toggleTheme: () => setTheme(theme === "dark" ? "light" : "dark"),
  }).concat(deployAppsForPalette.flatMap(app => {
    const server = servers.find(item => item.id === app.serverId);
    return server ? [{ id: `deploy:${app.id}:${server.id}`, title: `Open “${app.name}” deployments on ${server.name}`, category: "Deployments", run: () => { setPendingDeployApp({ serverId: server.id, appId: app.id }); openServerView(server, "deploy"); } }] : [];
  }));

  const activeStatus = activeTab ? statuses.get(activeTab.server.id) : undefined;
  const connectedCount = Array.from(statuses.values()).filter((status) => status === "ready").length;
  const failedCount = Array.from(statuses.values()).filter((status) => status === "error").length;
  const fleetStatus: SessionStatus | undefined = serversLoading ? "connecting" : failedCount > 0 ? "error" : connectedCount > 0 ? "ready" : undefined;
  const topStatusText = activeTab
    ? fleetLabel(activeStatus)
    : serversLoading
      ? "Loading profiles"
    : failedCount > 0
      ? `${failedCount} need${failedCount === 1 ? "s" : ""} attention`
      : connectedCount > 0
        ? `${connectedCount} connected`
        : servers.length === 0 ? "No servers" : "Fleet idle";

  const renderPaneContent = (key: string) => {
    const tab = tabs.find((item) => item.key === key);
    if (!tab) return null;
    const status = statuses.get(tab.server.id);
    const viewConnecting = CONNECTION_VIEWS.has(tab.view)
      && (!status || status === "connecting" || status === "authenticating");
    return (
        <section
          className="workspace-pane"
          aria-label={`${tab.server.name} workspace`}
          onPointerDownCapture={() => setActiveKey(tab.key)}
          onFocusCapture={() => setActiveKey(tab.key)}
        >
          <div className="workspace-pane-navigation">
            <nav className="subnav workspace-pane-subnav" aria-label={`${tab.server.name} quick views`}>
              {VIEWS.filter((view) => ["monitor", "terminal", "files", "logs"].includes(view.id)).map((view) => (
                <button type="button" key={view.id} aria-current={tab.view === view.id ? "page" : undefined}
                  className={`subnav-item ${tab.view === view.id ? "active" : ""}`}
                  onClick={() => setViewForKey(tab.key, view.id)}>{view.label}</button>
              ))}
            </nav>
            <OarsSelect value={tab.view} options={VIEWS.map((view) => ({ value: view.id, label: view.label }))}
              aria-label={`${tab.server.name} all views`} className="workspace-view-select"
              onValueChange={(value) => setViewForKey(tab.key, value as View)} />
          </div>

          <div className="workspace-pane-scroll" hidden={tab.view === "terminal"}>
            <div className="content workspace-pane-content">
              {viewConnecting ? (
                <OarsLoadingState
                  title={`Connecting to ${tab.server.name}`}
                  detail="Oars is opening a secure session before it loads this view."
                />
              ) : tab.view === "monitor" ? <MonitorTab key={tab.key} server={tab.server} />
                : tab.view === "logs" ? <LogsTab key={tab.key} server={tab.server} />
                : tab.view === "files" ? <FilesTab key={tab.key} serverId={tab.server.id} onNavigateToDeploy={() => setViewForKey(tab.key, "deploy")} />
                : tab.view === "scripts" ? <ScriptsTab key={tab.key} serverId={tab.server.id} servers={servers} statuses={statuses} connected={status === "ready"} initialScriptId={pendingScriptId} initialDraft={pendingScriptDraft?.tabKey === tab.key ? pendingScriptDraft.draft : null} onInitialDraftConsumed={() => setPendingScriptDraft((current) => current?.tabKey === tab.key ? null : current)} />
                : tab.view === "deploy" ? (
                  <DeployTab
                    key={tab.key}
                    serverId={tab.server.id}
                    initialAppId={pendingDeployApp?.serverId === tab.server.id ? pendingDeployApp.appId : null}
                    onAppsLoaded={(apps) => handleDeployAppsLoaded(tab.server.id, apps)}
                    onClearPendingApp={() => setPendingDeployApp(null)}
                  />
                )
                : tab.view === "keys" ? <KeysTab key={tab.key} serverId={tab.server.id} />
                : tab.view === "backups" ? <BackupsTab key={tab.key} serverId={tab.server.id} connected={statuses.get(tab.server.id) === "ready"} />
                : tab.view === "ai" ? <AiTab key={tab.key} serverId={tab.server.id} onOpenScriptDraft={(command, destructive) => {
                  setPendingScriptDraft({ tabKey: tab.key, draft: { name: "", description: "Drafted from an approved AI Terminal proposal. Review the command, variables, and destructive state before saving.", tags: destructive ? ["destructive"] : [], color: "", body: command, variables: [] } });
                  setViewForKey(tab.key, "scripts");
                }} />
                : tab.view === "vnc" ? (
                  <Suspense fallback={<OarsLoadingState title="Loading remote desktop" detail="Oars is preparing the secure VNC client." />}>
                    <VncTab key={tab.key} serverId={tab.server.id} />
                  </Suspense>
                )
                : tab.view === "history" ? <HistoryTab key={tab.key} serverId={tab.server.id} />
                : tab.view === "agent" ? <AgentTab key={tab.key} server={tab.server} />
                : <div className="empty"><h3>{VIEWS.find((view) => view.id === tab.view)?.label}</h3><p className="muted">Coming in the next spec — backend is ready.</p></div>}
            </div>
          </div>

          <div className="terminal-deck workspace-terminal-deck" hidden={tab.view !== "terminal"}>
            <TerminalTab server={tab.server} onStatus={setStatus} onServerUpdated={handleServerUpdated} />
          </div>
        </section>
    );
  };

  const togglePaneFocus = (key: string) => {
    setActiveKey(key);
    setPaneFocused((current) => !current);
    requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[data-pane-focus="true"]')?.focus());
  };

  const renderServerPane = (key: string, path: MosaicPath) => {
    const tab = tabs.find((item) => item.key === key);
    if (!tab) return <div />;
    const status = statuses.get(tab.server.id);
    const name = `${tab.server.name}${tab.key.includes("#") ? " · mirror" : ""}`;
    return <MosaicWindow<string>
      className={`oars-mosaic-window ${tab.key === activeKey ? "is-active" : ""}`}
      path={path} title={name} draggable={false}
      renderToolbar={() => (
        <div className="workspace-pane-toolbar" data-workspace-pane={key} onPointerDown={() => setActiveKey(key)}>
          <WorkspaceDragHandle paneKey={key} onFocusPane={() => togglePaneFocus(key)}>
            <GripVertical aria-hidden />
            <ConnectionStatus status={status} />
            <div className="workspace-pane-identity"><strong>{name}</strong>
              <span className="workspace-pane-address">{tab.server.user}@{tab.server.host}:{tab.server.port}</span>
            </div>
          </WorkspaceDragHandle>
          <div className="workspace-pane-actions" draggable={false}
            onDragStart={(event) => { event.preventDefault(); event.stopPropagation(); }}>
            <span className="workspace-pane-status">{fleetLabel(status)}</span>
            {!compactWorkspace && tabs.length > 1 && <Button variant="ghost" size="icon-sm"
              data-pane-focus={key === activeKey}
              aria-label={paneFocused ? "Restore pane layout" : `Focus ${name}`} title={paneFocused ? "Restore layout" : "Focus pane"}
              onClick={() => togglePaneFocus(key)}>
              {paneFocused ? <Minimize2 /> : <Maximize2 />}
            </Button>}
            <WorkspacePaneMenu name={name} canDuplicate={tabs.length < MAX_WORKSPACE_PANES}
              peers={tabs.filter((peer) => peer.key !== key).map((peer) => ({ key: peer.key, label: `${peer.server.name}${peer.key.includes("#") ? " · mirror" : ""}` }))}
              onDock={(target, position) => {
                customLayoutRef.current = true;
                setMosaicLayout((current) => dockWorkspacePane(current, key, target, position));
                setActiveKey(key); setPaneFocused(false); setWorkspaceMessage(`${name} moved.`);
              }} onDuplicate={() => openMirrored(tab.server, tab.view)}
              onEdit={() => setModal({ server: tab.server })} onClose={() => closeTab(key)} />
            <Button variant="ghost" size="icon-sm" aria-label={`Close ${name}`} title="Close pane" onClick={() => closeTab(key)}><X /></Button>
          </div>
        </div>
      )}
    ><WorkspacePaneSlot paneKey={key} /></MosaicWindow>;
  };

  return (
    <main className={`oars-app ${sidebarCollapsed ? "has-collapsed-sidebar" : ""}`}>
      <aside className={`sidebar ${sidebarCollapsed ? "sidebar-collapsed" : ""} ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Network /></div>
          <div className="brand-copy"><strong>oars</strong><span>LOCAL OPS</span></div>
          <Button
            variant="ghost"
            size="icon-sm"
            className="sidebar-collapse-toggle"
            onClick={() => setSidebarCollapsed((current) => !current)}
            aria-label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
            title={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {sidebarCollapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          </Button>
          <Button variant="ghost" size="icon-sm" className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X /></Button>
        </div>
        <div className="workspace-switcher" title="Workspace: Local machine">
          <div className="workspace-icon"><Cloud /></div>
          <div><span>Workspace</span><strong>Local machine</strong></div>
          <ChevronRight />
        </div>
        <nav>
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <p>{group.label}</p>
              {group.items.map((item) => (
                <button
                  key={item.label}
                  className={`nav-item ${!activeTab && activeSection === item.label ? "nav-active" : ""}`}
                  onClick={() => { setActiveSection(item.label as Section); setActiveGroup(null); setBroadcastGroupIds(undefined); setActiveKey(null); setMobileNav(false); }}
                  title={item.label}
                >
                  <item.icon />
                  <span className="nav-item-label">{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-fleet" aria-label="Fleet">
          <div className="sidebar-fleet-head">
            <span className="sidebar-fleet-title"><HardDrive size={13} aria-hidden /> Fleet</span>
            <span className="sidebar-fleet-count">{servers.length} {servers.length === 1 ? "profile" : "profiles"}</span>
          </div>
          <label className="sidebar-fleet-search" aria-label="Filter fleet">
            <Search size={12} aria-hidden />
            <input ref={fleetSearchRef} value={fleetFilter} onChange={(e) => setFleetFilter(e.target.value)} placeholder="Filter by name, host or group" aria-label="Filter fleet" />
            {fleetFilter && <button type="button" aria-label="Clear filter" onClick={() => setFleetFilter("")} style={{ border: 0, background: "transparent", color: "var(--muted-foreground)", cursor: "pointer", padding: 2 }}><X size={12} /></button>}
          </label>
          <FleetList groups={fleetGroups} collapsed={collapsedFleetGroups} expandAll={sidebarCollapsed} activeServerId={activeTab?.server.id}
            empty={serversLoading ? "Loading profiles…" : servers.length === 0 ? "No connection profiles yet." : "No matches."}
            renderGroup={group => {
              const collapsed = !sidebarCollapsed && collapsedFleetGroups.has(group.key);
              return (<div className="sidebar-group-header" data-fleet-group-drop={group.path}>
                    <Button variant="ghost" size="icon-xs" aria-label={`${collapsed ? "Expand" : "Collapse"} ${group.label}`} aria-expanded={!collapsed} onClick={() => toggleFleetGroup(group.key)}><ChevronDown className={collapsed ? "is-collapsed" : ""} aria-hidden /></Button>
                    <button type="button" className="sidebar-fleet-group-toggle" onClick={() => openGroup(group.path)}>
                      <span>{group.label}</span>
                      <span>{group.entries.filter(server => statuses.get(server.id) === "ready").length} connected · {group.entries.filter(server => statuses.get(server.id) === "error").length} errors · {group.entries.length} total</span>
                    </button>
                  </div>);
            }}
            renderServer={s => {
              const st = statuses.get(s.id);
                    const isActive = tabs.some((t) => t.server.id === s.id && t.key === activeKey);
                    return (
                      <div key={s.id} className={`sidebar-fleet-row ${isActive ? "is-active" : ""}`} role="listitem" data-server-menu>
                        <button type="button" className="sidebar-fleet-open" onPointerDown={event => fleetMove.onPointerDown(event, s)} onPointerMove={fleetMove.onPointerMove} onPointerUp={fleetMove.onPointerUp} onPointerCancel={fleetMove.onPointerCancel} onLostPointerCapture={fleetMove.onLostPointerCapture} onClick={() => { if (fleetMove.consumeClick()) return; openServer(s); setServerMenuId(null); setMobileNav(false); }} title={`${s.name} — ${s.host}:${s.port}`}>
                          <ConnectionStatus status={st} />
                          <span className="sidebar-fleet-meta">
                            <span className="sidebar-fleet-name">{s.name}</span>
                            <span className="sidebar-fleet-host">{s.host}:{s.port} · {s.user}</span>
                          </span>
                          <span className="sidebar-fleet-status">{fleetLabel(st)}</span>
                        </button>
                        <div className="sidebar-fleet-actions">
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label={`Actions for ${s.name}`}
                            aria-haspopup="menu"
                            aria-expanded={serverMenuId === s.id}
                            title="Server actions"
                            onClick={() => setServerMenuId((current) => current === s.id ? null : s.id)}
                          >
                            <MoreHorizontal />
                          </Button>
                          {serverMenuId === s.id && (
                            <div className="sidebar-server-menu" role="menu" aria-label={`Actions for ${s.name}`}>
                              <button type="button" role="menuitem" onClick={() => { openServerView(s, "terminal"); setServerMenuId(null); setMobileNav(false); }}><Terminal /> Open terminal</button>
                              <button type="button" role="menuitem" onClick={() => { openMirrored(s); setServerMenuId(null); setMobileNav(false); }}><Plus /> New mirrored tab</button>
                              <button type="button" role="menuitem" onClick={() => { setMoveServer(s); setServerMenuId(null); }}>Move to group…</button>
                              <button type="button" role="menuitem" onClick={() => { setModal({ server: s }); setServerMenuId(null); }}><Pencil /> Edit profile</button>
                            </div>
                          )}
                        </div>
                        {s.tags.length > 0 && <div className="oars-fleet-tags">{s.tags.map(tag => <button key={tag} type="button" onClick={() => setFleetFilter(tag)} aria-label={`Filter fleet by tag ${tag}`}>{tag}</button>)}</div>}
                      </div>
                    );
            }}
          />
          <div className="sidebar-fleet-add">
            <Button size="sm" onClick={() => setModal({})} aria-label="Add server" title="Add server"><Plus data-icon="inline-start" /><span>Add server</span></Button>
          </div>
        </div>
        <div className="sidebar-bottom">
          <button type="button" className="nav-item settings-entry" title="Settings" onClick={() => { setSettingsOpen(true); setMobileNav(false); }}><Settings /><span className="nav-item-label">Settings</span><kbd>{isMacPlatform() ? "⌘," : "Ctrl+,"}</kbd></button>
          <div className="connection-card">
            <LockKeyhole size={15} aria-hidden />
            <div><strong>Local workspace</strong><span>Stored on this device</span></div>
          </div>
          <div className="user-row">
            <div className="user-avatar"><UserRound /></div>
            <div><strong>Operator</strong><span>Local profile</span></div>

          </div>
        </div>
      </aside>

      <section className="main-area">
        <header className="topbar">
          <Button variant="ghost" size="icon-sm" className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu /></Button>
          <div className="breadcrumbs">
            <span>Oars</span>
            <ChevronRight />
            <strong>{activeTab ? activeTab.server.name : activeSection}</strong>
            {activeTab && <><ChevronRight /><span style={{ color: "var(--muted-foreground)", fontSize: 11 }}>{VIEWS.find((v) => v.id === activeTab.view)?.label}</span></>}
          </div>
          <div className="topbar-actions">
            <label className="search-box">
              <Search />
              <input ref={searchRef} value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search fleet..." aria-label="Search fleet" />
              <kbd><Command /> K</kbd>
            </label>
            <button
              type="button"
              className="theme-toggle"
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              <span className="theme-toggle-thumb">{theme === "dark" ? <Moon /> : <Sun />}</span>
            </button>
            {serversRefreshing && <OarsRefreshStatus label="Updating fleet" />}
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={serversRefreshing ? "Refreshing fleet" : "Refresh fleet"}
              disabled={serversLoading || serversRefreshing}
              onClick={() => { refreshServers(); setToast("Fleet refreshed."); setTimeout(() => setToast(""), 2000); }}
            >
              <RefreshCw className={serversRefreshing ? "spin" : ""} />
            </Button>
            <div className="top-status"><ConnectionStatus status={activeTab ? activeStatus : fleetStatus} /> {topStatusText}</div>
          </div>
        </header>

        {tabs.length > 0 && (
          <div className="tabbar">
            <div className="tabbar-tabs" role="tablist" aria-label="Open server views">
              {tabs.map((tab) => {
                const isMirror = tab.key.includes("#");
                return (
                  <div key={tab.key} className={`tab ${tab.key === activeKey ? "active" : ""}`}>
                    <button
                      type="button"
                      className="tab-select"
                      role="tab"
                      aria-selected={tab.key === activeKey}
                      onClick={() => { setActiveKey(tab.key); setWorkspaceNavigationRevision(revision => revision + 1); }}
                      title={isMirror ? `${tab.server.name} — mirrored view` : tab.server.name}
                    >
                      <ConnectionStatus status={statuses.get(tab.server.id)} />
                      <span>{tab.server.name}{isMirror ? " · mirror" : ""}</span>
                    </button>
                    <button type="button" className="tab-close" aria-label={`Close ${tab.server.name}${isMirror ? " mirror" : ""}`} title="Close tab" onClick={() => closeTab(tab.key)}><X /></button>
                  </div>
                );
              })}
            </div>
            <div className="workspace-layout-controls">
              <span>{compactWorkspace ? "Single pane" : paneFocused ? "Focused" : `${tabs.length} open`}</span>
              <WorkspaceLayoutPicker
                value={layoutVariant}
                defaultValue={defaultLayoutVariant}
                onChange={applyLayoutVariant}
                onSaveDefault={saveDefaultLayout}
              />
            </div>
          </div>
        )}

        {tabs.length > 0 && (
          <div className="workspace workspace-mosaic-host" hidden={!activeTab}>
            <WorkspaceSurfaces paneKeys={tabs.map((tab) => tab.key)} renderPane={renderPaneContent}>
            <WorkspaceDockTabContext.Provider value={{ names: Object.fromEntries(tabs.map((tab) => [tab.key, `${tab.server.name}${tab.key.includes("#") ? " · mirror" : ""}`])), onSelect: setActiveKey }}>
            <WorkspaceDocking enabled={!paneFocused && !compactWorkspace} onStatus={setWorkspaceMessage}
              onDock={(source, target, position) => {
                customLayoutRef.current = true;
                setMosaicLayout((current) => dockWorkspacePane(current, source, target, position));
                setActiveKey(source);
              }}>
            <WorkspacePages layout={mosaicLayout} activeKey={activeKey} focused={paneFocused || compactWorkspace} navigationRevision={workspaceNavigationRevision}
              onChange={setMosaicLayout} onRelease={() => { customLayoutRef.current = true; }} renderTile={renderServerPane} />
            </WorkspaceDocking>
            </WorkspaceDockTabContext.Provider>
            </WorkspaceSurfaces>
            <div className="workspace-statusbar"><span>{compactWorkspace ? "Select a server above to switch panes." : paneFocused ? "Focus mode · Restore from the pane header." : tabs.length > 4 ? "Scroll for more servers · Four panes per section · Double-click to focus" : "Drag a header to split or group · Double-click to focus"}</span>
              <span role="status" aria-live="polite">{workspaceMessage}</span></div>
            {loadError && <div className="form-error workspace-mosaic-error">{loadError}</div>}
          </div>
        )}

        {!activeTab && <div className="workspace">
          {serversLoading ? (
            <OarsLoadingState title="Loading your workspace" detail="Oars is reading local connection profiles and recent activity." />
          ) : activeSection === "Overview" ? (
            <Overview servers={servers} statuses={statuses} search={search} onAdd={() => setModal({})} onOpenServer={openServer} onAction={onAction} />
          ) : activeSection === "Servers" && activeGroup !== null ? (
            <GroupView key={activeGroup} group={activeGroup} servers={groupMembers(servers, activeGroup)} statuses={statuses} onStatus={setStatus} onOpen={openServer} onUpdated={updated => {
              updateGroupServers(updated);
              if (updated.length > 0 && updated.length === groupMembers(servers, activeGroup).length && updated.every(server => server.group === updated[0].group)) setActiveGroup(updated[0].group);
            }} onBack={() => setActiveGroup(null)} onOpenAll={() => {
              const members = groupMembers(servers, activeGroup);
              const newMembers = members.filter(server => !tabs.some(tab => tab.server.id === server.id));
              const available = Math.max(0, MAX_WORKSPACE_PANES - tabs.length);
              newMembers.slice(0, available).forEach(openServer);
              if (newMembers.length > available) setToast(`Opened ${available} profiles. The workspace limit is ${MAX_WORKSPACE_PANES}; close panes to open the remaining ${newMembers.length - available}.`);
              else if (members[0]) openServer(members[0]);
            }} onRunScript={() => { setBroadcastGroupIds(groupMembers(servers, activeGroup).map(server => server.id)); setActiveSection("Automation"); }} />
          ) : activeSection === "Servers" ? (
            <ServersView servers={servers} statuses={statuses} search={search} onOpen={openServer} onEdit={(s) => setModal({ server: s })} onAdd={() => setModal({})} />
          ) : activeSection === "Activity" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="History & audit" title="Activity" description="A durable local journal of commands, sessions, and system changes."/>
              <div className="panel" style={{ padding: 0, overflow: "hidden" }}><HistoryTab initialAction={historyAction} onActionConsumed={() => setHistoryAction(null)} reviewEntry={pendingHistory} onReviewConsumed={() => setPendingHistory(null)} /></div>
            </div>
          ) : activeSection === "Automation" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="Scripts & deployments" title="Automation" description="Run repeatable operations across one server or the entire fleet."/>
              {servers.length === 0 ? (
                <div className="panel" style={{ padding: 22 }}><div className="empty-state"><div className="empty-icon"><Zap /></div><h3>No servers yet</h3><p>Add a server to run scripts and deployments.</p><Button onClick={() => setModal({})}>Add server</Button></div></div>
              ) : (
                <div className="panel" style={{ padding: 0, overflow: "hidden", minHeight: 420 }}><ScriptsTab initialBroadcastServerIds={broadcastGroupIds} serverId={null} servers={servers} statuses={statuses} connected={false} onOpenServer={(id) => { const s = servers.find((x) => x.id === id); if (s) openServerView(s, "scripts"); }} /></div>
              )}
            </div>
          ) : activeSection === "Security" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="Fleet security" title="Security" description="Keep identities, keys, and access policy visible and controlled."/>
              {servers.length === 0 ? (
                <div className="panel" style={{ padding: 22 }}><div className="empty-state"><div className="empty-icon"><ShieldCheck /></div><h3>No servers</h3><p>Add a server to manage authorized keys and roles.</p></div></div>
              ) : (
                <div className="panel" style={{ padding: 0, overflow: "hidden", minHeight: 420 }}><AccessTab /></div>
              )}
            </div>
          ) : activeSection === "Backups" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="Data protection" title="Backups" description="Manage server backup jobs, review recent runs, and restore data."/>
              <ProtectionBackupsPanel servers={servers} statuses={statuses} onAdd={() => setModal({})} />
            </div>
          ) : (
            <div className="content-stack">
              <SectionTitle eyebrow="Remote access & AI" title="AI Context" description="Local provider configuration and the context available to your assistant."/>
              <section className="ai-server-picker" aria-label="Choose an AI server">
                <header><Bot size={24} aria-hidden /><div><h2>Choose a server to work with</h2><p>Review its context, configure your provider, and start a conversation.</p></div></header>
                {servers.length === 0 ? <Button onClick={() => setModal({})}><Plus /> Add server</Button> : <div className="ai-server-list">{servers.map(server => <button type="button" key={server.id} onClick={() => openServerView(server, "ai")}><Server size={18} aria-hidden /><span><strong>{server.name}</strong><small>{server.user}@{server.host}</small></span><ConnectionStatus status={statuses.get(server.id)} label /><ArrowUpRight size={16} aria-hidden /></button>)}</div>}
                <p className="muted">You choose the server and approve commands before they run.</p>
              </section>
            </div>
          )}
          {loadError && <div className="form-error" style={{ marginTop: 14 }}>{loadError}</div>}
        </div>}
      </section>

      {paletteTarget && <PaletteTargetDialog title={paletteTarget.title} servers={servers} onClose={() => setPaletteTarget(null)} onSelect={server => {
        if (paletteTarget.mirror) openMirrored(server); else openServerView(server, paletteTarget.view);
        if (paletteTarget.scriptId) setPendingScriptId(paletteTarget.scriptId);
        setPaletteTarget(null);
      }} />}
      {moveServer && <GroupEditDialog servers={[moveServer]} group={moveServer.group} onUpdated={updateGroupServers} onClose={() => setMoveServer(null)} />}
      {dataOpen && <DataSettings onClose={() => setDataOpen(false)} onImported={() => void refreshServers()} />}
      {settingsOpen && <AppearanceSettings onData={() => { setSettingsOpen(false); setDataOpen(true); }} onClose={() => setSettingsOpen(false)} />}
      {modal && <ServerModal server={modal.server} servers={servers} onClose={() => setModal(null)} onSaved={handleSaved} onDeleted={handleDeleted} />}

      {paletteOpen && <CommandPalette
        isOpen={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={paletteItems}
        query={paletteQ}
        onQueryChange={setPaletteQ}
      />}

      {toast && <ApplicationNotice><div className="toast"><Check /> {toast}</div></ApplicationNotice>}
    </main>
  );
}

export function ProtectionBackupsPanel({ servers, statuses, onAdd }: { servers: OarsServer[]; statuses: Map<string, SessionStatus>; onAdd?: () => void }) {
  const previewMode = readBackupPreviewMode();
  const [activeId, setActiveId] = useState(() => previewMode === null ? "" : servers[0]?.id ?? "");
  useEffect(() => {
    if (previewMode !== null && activeId === "" && servers[0] !== undefined) {
      setActiveId(servers[0].id);
      return;
    }
    if (activeId !== "" && !servers.some((server) => server.id === activeId)) setActiveId("");
  }, [activeId, previewMode, servers]);

  const activeServer = servers.find((server) => server.id === activeId) ?? null;
  const connected = activeServer !== null
    && (previewMode === "disconnected" ? false : previewMode !== null || statuses.get(activeServer.id) === "ready");
  const previewStatus: SessionStatus | null = previewMode === null
    ? null
    : previewMode === "disconnected" ? "closed" : "ready";
  const options = servers.map((server) => ({
    value: server.id,
    label: `${server.name} — ${server.host} · ${fleetLabel(previewStatus ?? statuses.get(server.id))}`,
  }));

  return (
    <div className="protection-backups-panel">
      {(activeServer !== null || servers.length === 0) && <div className="protection-backups-picker">
        <div className="protection-backups-picker-copy">
          <label htmlFor="protection-backup-server">Backup server</label>
          <span>Choose the server to manage.</span>
        </div>
        <div className="protection-backups-picker-control"><OarsSelect
          id="protection-backup-server"
          value={activeId === "" ? null : activeId}
          onValueChange={setActiveId}
          options={options}
          placeholder={servers.length === 0 ? "No servers available" : "Select a server"}
          disabled={servers.length === 0}
        /></div>
      </div>}
      {servers.length === 0 ? (
        <div className="backups-empty backups-empty-compact">
          <Server aria-hidden />
          <h3>No servers available</h3>
          <p>Add a server before configuring backup jobs.</p>{onAdd && <Button size="sm" onClick={onAdd}><Plus /> Add server</Button>}
        </div>
      ) : activeServer === null ? (
        <section className="backup-server-chooser"><header><h3>Select a server</h3><p>Open its backup jobs and run history.</p></header><div className="backup-server-list">{servers.map(server => <button key={server.id} type="button" aria-label={`Open backups for ${server.name}`} onClick={() => setActiveId(server.id)}><Server size={17} aria-hidden /><span><strong>{server.name}</strong><small>{server.user}@{server.host}:{server.port}</small></span><ConnectionStatus status={statuses.get(server.id)} label /><ArrowUpRight size={15} aria-hidden /></button>)}</div></section>
      ) : (
        <BackupsTab key={activeServer.id} serverId={activeServer.id} connected={connected} previewMode={previewMode} />
      )}
    </div>
  );
}
