import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Archive,
  ArrowUpRight,
  Bot,
  Check,
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
function statusDotClass(s: string) {
  if (s === "ready") return "status-dot";
  if (s === "error" || s === "closed") return "status-dot status-offline";
  return "status-dot";
}
function sessionStatusClass(s?: SessionStatus) {
  if (!s || s === "closed" || s === "error") return "closed";
  return s;
}
function initials(name: string) {
  const parts = name.split(/[-_\s]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}
function StatusDot({ status }: { status: string }) {
  const cls = status === "Online" ? "status-dot" : status === "Degraded" ? "status-dot status-degraded" : "status-dot status-offline";
  return <span className={cls} aria-label={status} />;
}
function MetricBar({ value, tone = "primary" }: { value: number; tone?: "primary" | "warning" }) {
  return (
    <div className="metric-track">
      <div className={`metric-fill ${tone === "warning" ? "metric-warning" : ""}`} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
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
        title="Good morning, operator"
        description={`A calm view of your local infrastructure. ${total === 0 ? "No servers yet — add one to get started." : `Last refresh moments ago · ${online} of ${total} online.`}`}
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
            { label: "Scan fleet", icon: RefreshCw },
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
            <th>Connection</th>
            <th>Group</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {servers.map((s) => {
            const st = statuses.get(s.id);
            const label = st === "ready" ? "Online" : st === "connecting" || st === "authenticating" || st === "needs_trust" ? "Connecting" : st === "error" ? "Error" : "Offline";
            const pct = st === "ready" ? 72 : st ? 40 : 8;
            const tone = st === "ready" ? "primary" as const : "warning" as const;
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
                    <span className={st === "ready" ? "status-dot" : st === "error" ? "status-dot status-offline" : "status-dot status-offline"} />
                    {label}
                  </span>
                </td>
                <td>
                  <div className="bar-cell">
                    <span>{st ?? "—"}</span>
                    <MetricBar value={pct} tone={st === "ready" ? "primary" : "warning"} />
                  </div>
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
                      const label = st === "ready" ? "Online" : st ? st : "Offline";
                      return (
                        <tr key={s.id}>
                          <td><div className="server-cell"><span className="server-avatar">{initials(s.name)}</span><div><strong>{s.name}</strong><span>{s.host}:{s.port}</span></div></div></td>
                          <td style={{ color: "var(--muted-foreground)", fontSize: 11 }}>{s.user}</td>
                          <td><span className="pill" style={{ textTransform: "capitalize" }}>{s.auth_method}</span></td>
                          <td><span className="status-label"><span className={statusDotClass(label)} />{label}</span></td>
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
  const [activeSection, setActiveSection] = useState<Section>("Overview");
  const [mobileNav, setMobileNav] = useState(false);
  const [toast, setToast] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  const refreshServers = useCallback(async () => {
    try {
      const r = await api.servers.list();
      setServers(r.servers);
      setLoadError(null);
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

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
      if (e.key === "Escape" && paletteOpen) setPaletteOpen(false);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [paletteOpen]);

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
      const tab: Tab = { server, key: server.id, view: "monitor" };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, []);

  const setView = useCallback((view: View) => {
    setTabs((prev) => prev.map((t) => (t.key === activeKey ? { ...t, view } : t)));
  }, [activeKey]);

  const closeTab = useCallback((key: string) => {
    setTabs((prev) => {
      const tab = prev.find((t) => t.key === key);
      if (tab) api.ssh.disconnect(tab.server.id).catch(() => {});
      const next = prev.filter((t) => t.key !== key);
      setActiveKey((active) => (active === key ? (next[next.length - 1]?.key ?? null) : active));
      return next;
    });
  }, []);

  const handleSaved = useCallback((saved: OarsServer) => {
    setModal(null);
    refreshServers();
    setTabs((prev) => prev.map((t) => (t.server.id === saved.id ? { ...t, server: saved } : t)));
    openServer(saved);
  }, [refreshServers, openServer]);

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null;

  function onAction(label: string) {
    // fleet-level quick actions map to real UX
    if (label === "Open shell") {
      if (activeTab) setView("terminal");
      else if (servers[0]) openServer(servers[0]);
      else setToast("Add a server first to open a shell.");
    } else if (label === "Run a script") {
      if (activeTab) setView("scripts");
      else if (servers[0]) openServer(servers[0]);
      else setToast("Add a server first to run scripts.");
    } else if (label === "Scan fleet" || label === "Fleet refresh") {
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
    if (label !== "Fleet refresh" && label !== "Scan fleet") {
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
      for (const v of VIEWS) items.push({ label: `${s.name} → ${v.label}`, action: () => { openServer(s); setTimeout(() => setView(v.id), 30); setPaletteOpen(false); } });
    }
    items.push({ label: "Add server…", action: () => { setModal({}); setPaletteOpen(false); } });
    items.push({ label: `Theme: switch to ${theme === "dark" ? "light" : "dark"}`, action: () => { setTheme(theme === "dark" ? "light" : "dark"); setPaletteOpen(false); } });
    if (!paletteQ) return items.slice(0, 20);
    const q = paletteQ.toLowerCase();
    return items.filter((i) => i.label.toLowerCase().includes(q)).slice(0, 20);
  })();

  const topStatusOnline = activeTab ? statuses.get(activeTab.server.id) === "ready" : servers.length > 0;
  const topStatusText = activeTab
    ? (statuses.get(activeTab.server.id) ?? "closed")
    : topStatusOnline ? "All systems normal" : servers.length === 0 ? "No servers" : "Fleet idle";

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
                  {item.label === "Activity" && <span className="nav-count">5</span>}
                </button>
              ))}
            </div>
          ))}
        </nav>
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
            <div className="top-status"><span className={topStatusOnline ? "status-dot" : "status-dot status-offline"} /> {topStatusText}</div>
          </div>
        </header>

        {tabs.length > 0 && (
          <div className="tabbar">
            {tabs.map((tab) => (
              <button key={tab.key} className={`tab ${tab.key === activeKey ? "active" : ""}`} onClick={() => setActiveKey(tab.key)}>
                <span className={`dot ${sessionStatusClass(statuses.get(tab.server.id))}`} />
                {tab.server.name}
                <span className="close" role="button" tabIndex={0} onClick={(e) => { e.stopPropagation(); closeTab(tab.key); }}>×</span>
              </button>
            ))}
          </div>
        )}

        <div className="workspace">
          {activeTab ? (
            <div className="workspace" style={{ padding: 0, maxWidth: "none", margin: 0 }}>
              <div className="workspace-header">
                <div className="ws-title">
                  <span className="ws-name">{activeTab.server.name}</span>
                  <span className="ws-meta">{activeTab.server.host}:{activeTab.server.port} · {activeTab.server.user}{activeTab.server.group ? ` · ${activeTab.server.group}` : ""}</span>
                </div>
                <div className="ws-actions">
                  <span className={`dot ${sessionStatusClass(statuses.get(activeTab.server.id))}`} />
                  <span className="ws-status">{statuses.get(activeTab.server.id) ?? "closed"}</span>
                  <Button variant="ghost" size="sm" onClick={() => setModal({ server: activeTab.server })}>Edit</Button>
                </div>
              </div>
              <nav className="subnav">
                {VIEWS.map((v) => (
                  <button key={v.id} className={`subnav-item ${activeTab.view === v.id ? "active" : ""}`} onClick={() => setView(v.id)}>{v.label}</button>
                ))}
              </nav>
              <div className="content">
                {activeTab.view === "monitor" ? <MonitorTab key={activeTab.key} serverId={activeTab.server.id} />
                  : activeTab.view === "terminal" ? <TerminalTab key={activeTab.key} server={activeTab.server} onStatus={setStatus} />
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
              </div>
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
          {loadError && <div className="form-error" style={{ marginTop: 14 }}>{loadError}</div>}
        </div>
      </section>

      {modal && <ServerModal server={modal.server} onClose={() => setModal(null)} onSaved={handleSaved} />}

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
