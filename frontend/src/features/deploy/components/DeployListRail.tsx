import { useEffect, useState } from "react";
import { CloudCog, Plus, RefreshCw, Server } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { OarsRefreshStatus } from "../../../components/OarsLoadingState";
import type { DeployApp } from "../../../types";

export interface DeployListRailProps {
  apps: DeployApp[];
  selectedId: string | null;
  loading: boolean;
  onSelectApp: (appId: string) => void;
  onNewApp: () => void;
  onRefresh: () => void;
}

export function DeployListRail({
  apps,
  selectedId,
  loading,
  onSelectApp,
  onNewApp,
  onRefresh,
}: DeployListRailProps) {
  const [focusedIndex, setFocusedIndex] = useState(0);

  useEffect(() => {
    setFocusedIndex((prev) => {
      if (apps.length === 0) return 0;
      if (prev >= apps.length) return apps.length - 1;
      return prev;
    });
  }, [apps.length]);

  const handleKeyDown = (event: React.KeyboardEvent, app: DeployApp, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = Math.min(apps.length - 1, index + 1);
      setFocusedIndex(next);
      const btns = document.querySelectorAll<HTMLButtonElement>(".deploy-app-list .deploy-app-row");
      btns[next]?.focus();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prev = Math.max(0, index - 1);
      setFocusedIndex(prev);
      const btns = document.querySelectorAll<HTMLButtonElement>(".deploy-app-list .deploy-app-row");
      btns[prev]?.focus();
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setFocusedIndex(0);
      const btns = document.querySelectorAll<HTMLButtonElement>(".deploy-app-list .deploy-app-row");
      btns[0]?.focus();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      const last = apps.length - 1;
      setFocusedIndex(last);
      const btns = document.querySelectorAll<HTMLButtonElement>(".deploy-app-list .deploy-app-row");
      btns[last]?.focus();
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelectApp(app.id);
      return;
    }
  };

  return (
    <aside className="deploy-sidebar">
      <div className="deploy-sidebar-heading">
        <div>
          <span className="deploy-kicker">Applications</span>
          <strong>{apps.length} configured</strong>
        </div>
        <Button size="icon-sm" aria-label="New application" onClick={onNewApp}>
          <Plus />
        </Button>
      </div>
      {loading && <OarsRefreshStatus label="Updating applications" />}
      <div className="deploy-app-list" role="listbox" aria-label="Applications">
        {apps.map((app, index) => {
          const active = selectedId === app.id;
          const isFocused = index === focusedIndex || (focusedIndex === -1 && active);
          return (
            <button
              key={app.id}
              type="button"
              role="option"
              tabIndex={isFocused ? 0 : -1}
              aria-selected={active}
              className={`deploy-app-row${active ? " is-selected" : ""}`}
              onFocus={() => setFocusedIndex(index)}
              onClick={() => onSelectApp(app.id)}
              onKeyDown={(e) => handleKeyDown(e, app, index)}
            >
              <span className="deploy-app-mark">
                <Server />
              </span>
              <span className="deploy-app-copy">
                <strong>{app.name}</strong>
                <small>
                  {app.environment} · {app.repo.branch}
                </small>
                <small className="deploy-app-folder">{app.folder}</small>
              </span>
              <span className="deploy-app-chevron">›</span>
            </button>
          );
        })}
        {!apps.length && (
          <div className="deploy-empty-small">
            <CloudCog />
            <strong>No applications yet</strong>
            <span>Add a repository to prepare its first deployment.</span>
          </div>
        )}
      </div>
      <Button variant="outline" onClick={onRefresh} disabled={loading}>
        <RefreshCw />
        Refresh
      </Button>
    </aside>
  );
}
