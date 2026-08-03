import { useCallback, useEffect, useState } from "react";
import { api, BridgeError } from "./bridge";
import type { Server, SessionStatus } from "./types";
import { TerminalTab } from "./TerminalTab";
import { ServerModal } from "./ServerModal";

interface Tab {
  server: Server;
  key: string; // server.id + session generation
}

type ConnectionState = Map<string, SessionStatus>;

export default function App() {
  const [servers, setServers] = useState<Server[]>([]);
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<ConnectionState>(new Map());
  const [modal, setModal] = useState<{ server?: Server } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const refreshServers = useCallback(async () => {
    try {
      const r = await api.servers.list();
      setServers(r.servers);
      setLoadError(null);
    } catch (e) {
      setLoadError(e instanceof BridgeError ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refreshServers();
  }, [refreshServers]);

  const setStatus = useCallback((serverId: string, status: SessionStatus) => {
    setStatuses((prev) => {
      const next = new Map(prev);
      next.set(serverId, status);
      return next;
    });
  }, []);

  const openServer = useCallback((server: Server) => {
    setTabs((prev) => {
      const existing = prev.find((t) => t.server.id === server.id);
      if (existing) {
        setActiveKey(existing.key);
        return prev;
      }
      const tab: Tab = { server, key: `${server.id}:${Date.now()}` };
      setActiveKey(tab.key);
      return [...prev, tab];
    });
  }, []);

  const closeTab = useCallback((key: string) => {
    setTabs((prev) => {
      const tab = prev.find((t) => t.key === key);
      if (tab) api.ssh.disconnect(tab.server.id).catch(() => {});
      const next = prev.filter((t) => t.key !== key);
      setActiveKey((active) => (active === key ? next[next.length - 1]?.key ?? null : active));
      return next;
    });
  }, []);

  const handleSaved = useCallback((saved: Server) => {
    setModal(null);
    refreshServers();
    openServer(saved);
  }, [refreshServers, openServer]);

  const activeTab = tabs.find((t) => t.key === activeKey) ?? null;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo">Oars</span>
          <span className="tagline">Server Console</span>
        </div>
        <div className="sidebar-section">Servers</div>
        <nav className="server-list">
          {servers.map((server) => (
            <ServerRow
              key={server.id}
              server={server}
              status={statuses.get(server.id)}
              active={activeTab?.server.id === server.id}
              onOpen={() => openServer(server)}
              onEdit={() => setModal({ server })}
            />
          ))}
          {loadError && <div className="form-error" style={{ padding: "8px 10px" }}>{loadError}</div>}
        </nav>
        <div className="sidebar-footer">
          {servers.length} server{servers.length === 1 ? "" : "s"} · local-first
        </div>
        <button className="add-server" onClick={() => setModal({})}>
          + Add server
        </button>
      </aside>

      <main className="main">
        <div className="tabbar">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              className={`tab ${tab.key === activeKey ? "active" : ""}`}
              onClick={() => setActiveKey(tab.key)}
            >
              <span className={`dot ${statusClass(statuses.get(tab.server.id))}`} />
              {tab.server.name}
              <span
                className="close"
                role="button"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(tab.key);
                }}
              >
                ×
              </span>
            </button>
          ))}
        </div>
        <div className="content">
          {activeTab ? (
            <TerminalTab
              key={activeTab.key}
              server={activeTab.server}
              onStatus={setStatus}
            />
          ) : (
            <Dashboard onAdd={() => setModal({})} serverCount={servers.length} />
          )}
        </div>
      </main>

      {modal && (
        <ServerModal
          server={modal.server}
          onClose={() => setModal(null)}
          onSaved={handleSaved}
        />
      )}
    </div>
  );
}

function statusClass(status: SessionStatus | undefined): string {
  return status ?? "closed";
}

function ServerRow({
  server,
  status,
  active,
  onOpen,
  onEdit,
}: {
  server: Server;
  status?: SessionStatus;
  active: boolean;
  onOpen: () => void;
  onEdit: () => void;
}) {
  return (
    <div className={`server-item ${active ? "active" : ""}`} onClick={onOpen}>
      <span className={`dot ${statusClass(status)}`} />
      <span className="name">{server.name}</span>
      <span className="host">{server.host}</span>
      <button
        className="edit"
        title="Edit server"
        onClick={(e) => {
          e.stopPropagation();
          onEdit();
        }}
      >
        ✎
      </button>
    </div>
  );
}

function Dashboard({ onAdd, serverCount }: { onAdd: () => void; serverCount: number }) {
  return (
    <div className="dashboard">
      <div className="empty">
        <h2>{serverCount === 0 ? "No servers yet" : "Select a server"}</h2>
        <p>
          {serverCount === 0
            ? "Add the first server you manage. Oars connects over standard SSH — no agent to install, and your keys never leave this machine."
            : "Pick a server on the left, or add another one to your fleet."}
        </p>
        {serverCount === 0 && (
          <button className="cta" onClick={onAdd}>
            Add your first server
          </button>
        )}
        <div className="hint">ssh · sftp · exec — everything stays local</div>
      </div>
    </div>
  );
}
