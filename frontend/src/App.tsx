import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Archive,
  ArrowUpRight,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Cloud,
  Command,
  Database,
  Gauge,
  HardDrive,
  KeyRound,
  LayoutDashboard,
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
import { Button } from "./components/ui/button";
import { api, BridgeError } from "./bridge";
import type { Server as OarsServer, SessionStatus } from "./types";
import { TerminalTab } from "./TerminalTab";
import { ServerModal } from "./ServerModal";
import { MonitorTab } from "./MonitorTab";
import { LogsTab } from "./LogsTab";
import { FilesTab } from "./FilesTab";
import { ScriptsTab } from "./ScriptsTab";
import { DeployTab } from "./DeployTab";
import { KeysTab } from "./KeysTab";
import { AccessTab } from "./AccessTab";
import { BackupsTab } from "./BackupsTab";
import { AiTab } from "./AiTab";
import { VncTab } from "./VncTab";
import { HistoryTab } from "./HistoryTab";
import { VaultTab } from "./VaultTab";
import { AgentTab } from "./AgentTab";

// ---------------------------------------------------------------------------
// Shell nav
// ---------------------------------------------------------------------------
type Section = "Overview" | "Servers" | "Activity" | "Automation" | "Security" | "Backups" | "AI Context";
type View = "monitor" | "terminal" | "logs" | "files" | "scripts" | "deploy" | "keys" | "access" | "backups" | "ai" | "vnc" | "history" | "vault" | "agent";

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
  { id: "access", label: "Access" },
  { id: "backups", label: "Backups" },
  { id: "ai", label: "AI" },
  { id: "vnc", label: "VNC" },
  { id: "history", label: "History" },
  { id: "vault", label: "Vault" },
  { id: "agent", label: "Agent" },
];

const navGroups = [
  { label: "Workspace", items: [{ label: "Overview", icon: LayoutDashboard }, { label: "Servers", icon: Server }, { label: "Activity", icon: Activity }] },
  { label: "Operations", items: [{ label: "Automation", icon: Zap }, { label: "Security", icon: ShieldCheck }, { label: "Backups", icon: Archive }] },
  { label: "Intelligence", items: [{ label: "AI Context", icon: Bot }] },
] as const;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function sessionStatusClass(s?: SessionStatus) {
  if (!s || s === "closed") return "closed";
  return s;
}
function fleetDotClass(s?: SessionStatus): string {
  if (s === "ready") return "fleet-dot fleet-dot-ready";
  if (s === "connecting" || s === "authenticating") return "fleet-dot fleet-dot-connecting";
  if (s === "needs_trust") return "fleet-dot fleet-dot-needs_trust";
  if (s === "error") return "fleet-dot fleet-dot-error";
  return "fleet-dot fleet-dot-offline";
}
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

  const online = filtered.filter((s) => statuses.get(s.id) === "ready").length;
  const total = filtered.length;
  const health = total === 0 ? 0 : Math.round((online / total) * 100);
  const active = Array.from(statuses.values()).filter((v) => v === "ready").length;

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
            title: e.action ?? e.type ?? "Activity",
            detail: e.detail ?? e.server_id ?? "",
            time: "recent",
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
        title="Local infrastructure"
        description={total === 0 ? "No servers yet. Add one to get started." : `${online} of ${total} connection profiles are connected.`}
        action={
          <Button onClick={onAdd}>
            <Plus data-icon="inline-start" /> Add server
          </Button>
        }
      />

      <div className="metric-grid">
        {[
          { label: "Fleet health", value: `${health}%`, helper: `${online} of ${total} servers online`, icon: Gauge, tone: "success" as const },
          { label: "Active sessions", value: String(active).padStart(2, "0"), helper: `${active} shells · local`, icon: Terminal, tone: "info" as const },
          { label: "Servers", value: String(total).padStart(2, "0"), helper: `${filtered.length} in fleet`, icon: ListChecks, tone: "warning" as const },
          { label: "Storage used", value: "—", helper: "Per-server in Monitor", icon: Database, tone: "muted" as const },
        ].map((item) => (
          <div className="metric-card" key={item.label}>
            <div className={`metric-icon tone-${item.tone}`}>
              <item.icon />
            </div>
            <div>
              <p>{item.label}</p>
              <strong>{item.value}</strong>
              <span>{item.helper}</span>
            </div>
          </div>
        ))}
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
              No servers yet. Add your first one — Oars connects over standard SSH, no agent required.
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
          <h2>Keep moving</h2>
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
                    <span className={fleetDotClass(st)} aria-hidden />
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
                          <td><span className="status-label"><span className={fleetDotClass(st)} aria-hidden />{fleetLabel(st)}</span></td>
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
  const [servers, setServers] = useState<OarsServer[]>([]);
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Map<string, SessionStatus>>(new Map());
  const [modal, setModal] = useState<{ server?: OarsServer } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQ, setPaletteQ] = useState("");
  const [theme, setTheme] = useState<string>(() => {
    try {
      return localStorage.getItem("oars:theme") ?? "light";
    } catch {
      return "light";
    }
  });
  const [search, setSearch] = useState("");
  const [fleetFilter, setFleetFilter] = useState("");
  const fleetCountRef = useRef(0);
  const [collapsedFleetGroups, setCollapsedFleetGroups] = useState<Set<string>>(new Set());
  const [serverMenuId, setServerMenuId] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<Section>("Overview");
  const [mobileNav, setMobileNav] = useState(false);
  const [toast, setToast] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const fleetSearchRef = useRef<HTMLInputElement>(null);

  const refreshServers = useCallback(async () => {
    try {
      const r = await api.servers.list();
      setServers(r.servers);
      setLoadError(r.recovery_error ?? null);
    } catch (e) {
      setLoadError(e instanceof BridgeError ? e.message : String(e));
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
      vt.call(document, doSwap).finished.finally(cleanup);
    } else {
      doSwap();
      cleanup();
    }
  }, []);

  useEffect(() => { applyTheme(theme); }, [theme, applyTheme]);



  const setStatus = useCallback((serverId: string, status: SessionStatus) => {
    setStatuses((prev) => {
      const next = new Map(prev);
      next.set(serverId, status);
      return next;
    });
  }, []);

  const openServer = useCallback((server: OarsServer) => {
    setTabs((prev) => {
      const existing = prev.find((t) => t.server.id === server.id);
      if (existing) {
        setActiveKey(existing.key);
        return prev;
      }
      const tab: Tab = { server, key: server.id, view: "terminal" };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, []);

  const openServerView = useCallback((server: OarsServer, view: View) => {
    setTabs((prev) => {
      const existing = prev.find((t) => t.server.id === server.id);
      if (existing) {
        setActiveKey(existing.key);
        return prev.map((tab) => tab.key === existing.key ? { ...tab, view } : tab);
      }
      const tab: Tab = { server, key: server.id, view };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, []);

  const openMirrored = useCallback((server: OarsServer, view: View = "terminal") => {
    fleetCountRef.current += 1;
    const tab: Tab = { server, key: `${server.id}#${fleetCountRef.current}`, view };
    setTabs((prev) => [...prev, tab]);
    setActiveKey(tab.key);
  }, []);

  const setView = useCallback((view: View) => {
    setTabs((prev) => prev.map((t) => (t.key === activeKey ? { ...t, view } : t)));
  }, [activeKey]);

  const closeTab = useCallback((key: string) => {
    const tab = tabs.find((item) => item.key === key);
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
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "t") {
        const active = tabs.find((t) => t.key === activeKey);
        if (active) {
          e.preventDefault();
          openMirrored(active.server);
          return;
        }
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "f") {
        // Fleet search — don't hijack when the terminal or an input is focused.
        const tag = (document.activeElement?.tagName ?? "").toLowerCase();
        const inField = tag === "input" || tag === "textarea" || (document.activeElement as HTMLElement | null)?.isContentEditable;
        if (!inField) {
          e.preventDefault();
          fleetSearchRef.current?.focus();
          return;
        }
      }
      if (e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const tag = (document.activeElement?.tagName ?? "").toLowerCase();
        const inField = tag === "input" || tag === "textarea" || (document.activeElement as HTMLElement | null)?.isContentEditable;
        if (!inField) {
          e.preventDefault();
          fleetSearchRef.current?.focus();
        }
      }
      if (e.key === "Escape" && paletteOpen) setPaletteOpen(false);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [paletteOpen, tabs, activeKey, openMirrored]);

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

  const paletteItems = (() => {
    const items: Array<{ label: string; action: () => void }> = [];
    // sections
    for (const g of navGroups) for (const it of g.items) items.push({ label: `Go to ${it.label}`, action: () => { setActiveSection(it.label as Section); setActiveKey(null); setPaletteOpen(false); } });
    for (const s of servers) {
      items.push({ label: `Open ${s.name} (${s.host})`, action: () => { openServer(s); setPaletteOpen(false); } });
      items.push({ label: `Mirror ${s.name} in new tab`, action: () => { openMirrored(s); setPaletteOpen(false); } });
      for (const v of VIEWS) items.push({ label: `${s.name} → ${v.label}`, action: () => { openServerView(s, v.id); setPaletteOpen(false); } });
    }
    items.push({ label: "Add server…", action: () => { setModal({}); setPaletteOpen(false); } });
    items.push({ label: `Theme: switch to ${theme === "dark" ? "light" : "dark"}`, action: () => { setTheme(theme === "dark" ? "light" : "dark"); setPaletteOpen(false); } });
    if (!paletteQ) return items.slice(0, 20);
    const q = paletteQ.toLowerCase();
    return items.filter((i) => i.label.toLowerCase().includes(q)).slice(0, 20);
  })();

  const activeStatus = activeTab ? statuses.get(activeTab.server.id) : undefined;
  const connectedCount = Array.from(statuses.values()).filter((status) => status === "ready").length;
  const failedCount = Array.from(statuses.values()).filter((status) => status === "error").length;
  const fleetStatus: SessionStatus | undefined = failedCount > 0 ? "error" : connectedCount > 0 ? "ready" : undefined;
  const topStatusText = activeTab
    ? fleetLabel(activeStatus)
    : failedCount > 0
      ? `${failedCount} need${failedCount === 1 ? "s" : ""} attention`
      : connectedCount > 0
        ? `${connectedCount} connected`
        : servers.length === 0 ? "No servers" : "Fleet idle";

  return (
    <main className="oars-app">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Network /></div>
          <div><strong>oars</strong><span>LOCAL OPS</span></div>
          <Button variant="ghost" size="icon-sm" className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X /></Button>
        </div>
        <div className="workspace-switcher">
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
                  onClick={() => { setActiveSection(item.label as Section); setActiveKey(null); setMobileNav(false); }}
                >
                  <item.icon />
                  {item.label}
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
          <div className="sidebar-fleet-list" role="list">
            {fleetGroups.length === 0 ? (
              <div className="sidebar-fleet-empty">{servers.length === 0 ? "No connection profiles yet." : "No matches."}</div>
            ) : fleetGroups.map((group) => {
              const collapsed = collapsedFleetGroups.has(group.key);
              return (
                <div className="sidebar-fleet-group" key={group.key}>
                  <button
                    type="button"
                    className="sidebar-fleet-group-toggle"
                    aria-expanded={!collapsed}
                    onClick={() => toggleFleetGroup(group.key)}
                  >
                    <ChevronDown className={collapsed ? "is-collapsed" : ""} aria-hidden />
                    <span>{group.label}</span>
                    <span>{group.entries.length}</span>
                  </button>
                  {!collapsed && group.entries.map((s) => {
                    const st = statuses.get(s.id);
                    const isActive = tabs.some((t) => t.server.id === s.id && t.key === activeKey);
                    return (
                      <div key={s.id} className={`sidebar-fleet-row ${isActive ? "is-active" : ""}`} role="listitem" data-server-menu>
                        <button type="button" className="sidebar-fleet-open" onClick={() => { openServer(s); setServerMenuId(null); }} title={`${s.name} — ${s.host}:${s.port}`}>
                          <span className={fleetDotClass(st)} aria-hidden />
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
                              <button type="button" role="menuitem" onClick={() => { openServerView(s, "terminal"); setServerMenuId(null); }}><Terminal /> Open terminal</button>
                              <button type="button" role="menuitem" onClick={() => { openMirrored(s); setServerMenuId(null); }}><Plus /> New mirrored tab</button>
                              <button type="button" role="menuitem" onClick={() => { setModal({ server: s }); setServerMenuId(null); }}><Pencil /> Edit profile</button>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
          <div className="sidebar-fleet-add">
            <Button size="sm" onClick={() => setModal({})}><Plus data-icon="inline-start" /> Add server</Button>
          </div>
        </div>
        <div className="sidebar-bottom">
          <div className="connection-card">
            <span className="connection-pulse" />
            <div><strong>Native bridge</strong><span>Connected · zero://app</span></div>
          </div>
          <div className="user-row">
            <div className="user-avatar"><UserRound /></div>
            <div><strong>Operator</strong><span>Local profile</span></div>
            <Button variant="ghost" size="icon-xs" aria-label="Help"><CircleHelp /></Button>
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
            <Button variant="ghost" size="icon-sm" aria-label="Refresh fleet" onClick={() => { refreshServers(); setToast("Fleet refreshed."); setTimeout(() => setToast(""), 2000); }}><RefreshCw /></Button>
            <div className="top-status"><span className={fleetDotClass(activeTab ? activeStatus : fleetStatus)} aria-hidden /> {topStatusText}</div>
          </div>
        </header>

        {tabs.length > 0 && (
          <div className="tabbar" role="tablist" aria-label="Open server views">
            {tabs.map((tab) => {
              const isMirror = tab.key.includes("#");
              return (
                <div key={tab.key} className={`tab ${tab.key === activeKey ? "active" : ""}`}>
                  <button
                    type="button"
                    className="tab-select"
                    role="tab"
                    aria-selected={tab.key === activeKey}
                    onClick={() => setActiveKey(tab.key)}
                    title={isMirror ? `${tab.server.name} — mirrored view` : tab.server.name}
                  >
                    <span className={`dot ${sessionStatusClass(statuses.get(tab.server.id))}`} aria-hidden />
                    <span>{tab.server.name}{isMirror ? " · mirror" : ""}</span>
                  </button>
                  <button type="button" className="tab-close" aria-label={`Close ${tab.server.name}${isMirror ? " mirror" : ""}`} title="Close tab" onClick={() => closeTab(tab.key)}><X /></button>
                </div>
              );
            })}
          </div>
        )}

        <div className="workspace">
          {activeTab ? (
            <div className="workspace-inner">
              <div className="workspace-header">
                <div className="ws-title">
                  <span className="ws-name">{activeTab.server.name}</span>
                  <span className="ws-meta">{activeTab.server.user}@{activeTab.server.host}:{activeTab.server.port}{activeTab.server.group ? ` · ${activeTab.server.group}` : ""}</span>
                </div>
                <div className="ws-actions">
                  <span className={`dot ${sessionStatusClass(statuses.get(activeTab.server.id))}`} />
                  <span className="ws-status">{statuses.get(activeTab.server.id) ?? "closed"}</span>
                  <Button variant="ghost" size="sm" onClick={() => setModal({ server: activeTab.server })}>Edit</Button>
                </div>
              </div>
              <nav className="subnav" role="tablist">
                {VIEWS.map((v) => (
                  <button key={v.id} role="tab" aria-selected={activeTab.view === v.id} className={`subnav-item ${activeTab.view === v.id ? "active" : ""}`} onClick={() => setView(v.id)}>{v.label}</button>
                ))}
              </nav>
              {activeTab.view !== "terminal" && <div className="content">
                {activeTab.view === "monitor" ? <MonitorTab key={activeTab.key} server={activeTab.server} />
                  : activeTab.view === "logs" ? <LogsTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "files" ? <FilesTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "scripts" ? <ScriptsTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "deploy" ? <DeployTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "keys" ? <KeysTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "access" ? <AccessTab key={activeTab.key} />
                  : activeTab.view === "backups" ? <BackupsTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "ai" ? <AiTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "vnc" ? <VncTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "history" ? <HistoryTab key={activeTab.key} />
                  : activeTab.view === "vault" ? <VaultTab key={activeTab.key} />
                  : activeTab.view === "agent" ? <AgentTab key={activeTab.key} />
                  : <div className="empty"><h3>{VIEWS.find((x) => x.id === activeTab.view)?.label}</h3><p className="muted">Coming in the next spec — backend is ready.</p></div>}
              </div>}
            </div>
          ) : activeSection === "Overview" ? (
            <Overview servers={servers} statuses={statuses} search={search} onAdd={() => setModal({})} onOpenServer={openServer} onAction={onAction} />
          ) : activeSection === "Servers" ? (
            <ServersView servers={servers} statuses={statuses} search={search} onOpen={openServer} onEdit={(s) => setModal({ server: s })} onAdd={() => setModal({})} />
          ) : activeSection === "Activity" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="History & audit" title="Activity" description="A durable local journal of commands, sessions, and system changes."/>
              <div className="panel" style={{ padding: 0, overflow: "hidden" }}><HistoryTab /></div>
            </div>
          ) : activeSection === "Automation" ? (
            <div className="content-stack">
              <SectionTitle eyebrow="Scripts & deployments" title="Automation" description="Run repeatable operations across one server or the entire fleet."/>
              {servers.length === 0 ? (
                <div className="panel" style={{ padding: 22 }}><div className="empty-state"><div className="empty-icon"><Zap /></div><h3>No servers yet</h3><p>Add a server to run scripts and deployments.</p><Button onClick={() => setModal({})}>Add server</Button></div></div>
              ) : (
                <div className="panel" style={{ padding: 0, overflow: "hidden", minHeight: 420 }}><ScriptsTab serverId={servers[0].id} /></div>
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
              <SectionTitle eyebrow="Data protection" title="Backups" description="Encrypted jobs, vault portability, and restore history without cloud sync."/>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                <div className="panel" style={{ padding: 0, overflow: "hidden" }}><VaultTab /></div>
                <div className="panel" style={{ padding: 0, overflow: "hidden", minHeight: 320 }}>{servers[0] ? <BackupsTab serverId={servers[0].id} /> : <div style={{ padding: 22 }} className="muted">Add a server to configure backups.</div>}</div>
              </div>
            </div>
          ) : (
            <div className="content-stack">
              <SectionTitle eyebrow="Remote access & AI" title="AI Context" description="Local provider configuration and the context available to your assistant."/>
              {servers[0] ? <div className="panel" style={{ padding: 0, overflow: "hidden" }}><AiTab serverId={servers[0].id} /></div> : <div className="panel muted" style={{ padding: 22 }}>Add a server to see AI context.</div>}
            </div>
          )}
          <div className="terminal-deck" hidden={!activeTab || activeTab.view !== "terminal"}>
            {tabs.map((tab) => (
              <div key={tab.key} className="terminal-pane" hidden={tab.key !== activeKey || activeTab?.view !== "terminal"}>
                <TerminalTab server={tab.server} onStatus={setStatus} onServerUpdated={handleServerUpdated} />
              </div>
            ))}
          </div>
          {loadError && <div className="form-error" style={{ marginTop: 14 }}>{loadError}</div>}
        </div>
      </section>

      {modal && <ServerModal server={modal.server} servers={servers} onClose={() => setModal(null)} onSaved={handleSaved} onDeleted={handleDeleted} />}

      {paletteOpen && (
        <div className="overlay" onClick={() => setPaletteOpen(false)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()} style={{ width: 560, maxHeight: "70vh", display: "flex", flexDirection: "column" }}>
            <div style={{ padding: 12, borderBottom: "1px solid var(--border)" }}>
              <input autoFocus placeholder="Type a command or search…" value={paletteQ} onChange={(e) => setPaletteQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && paletteItems[0]) paletteItems[0].action(); }} style={{ width: "100%", background: "var(--background)", border: "1px solid var(--border)", color: "var(--foreground)", borderRadius: 8, padding: "10px 12px", fontSize: 13 }} />
            </div>
            <div style={{ overflow: "auto", padding: 8, display: "grid", gap: 4 }}>
              {paletteItems.map((it, i) => (
                <button key={i} onClick={it.action} style={{ textAlign: "left", background: i === 0 ? "var(--accent)" : "var(--background)", border: "1px solid var(--border)", color: i === 0 ? "var(--primary)" : "var(--foreground)", borderRadius: 6, padding: "8px 10px", fontSize: 12, cursor: "pointer" }}>{it.label}</button>
              ))}
              {paletteItems.length === 0 && <div className="muted" style={{ padding: 12, fontSize: 12 }}>No matches</div>}
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast"><Check /> {toast}</div>}
    </main>
  );
}
