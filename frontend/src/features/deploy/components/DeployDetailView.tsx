import { CheckCircle2, Code2, ExternalLink, History, Pencil, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { DeployApp, DeployHistoryRecord } from "../../../types";

export interface DeployDetailViewProps {
  app: DeployApp;
  displayStatus: string;
  latest: DeployHistoryRecord | null;
  history: DeployHistoryRecord[];
  onEdit: () => void;
  onDelete: () => void;
  onRefreshHistory: () => void;
}

export function runLabel(status: string): string {
  if (status === "done") return "Live";
  if (status === "running" || status === "queued") return "Deploying";
  if (status === "cancel_requested") return "Cancel requested";
  if (status === "failed" || status === "interrupted") return "Needs attention";
  if (status === "canceled") return "Canceled";
  return "Not deployed";
}

export function DeployDetailView({
  app,
  displayStatus,
  latest,
  history,
  onEdit,
  onDelete,
  onRefreshHistory,
}: DeployDetailViewProps) {
  const publicUrl = app.domains[0] ? `${app.ssl ? "https" : "http"}://${app.domains[0]}` : null;

  return (
    <>
      <header className="deploy-hero">
        <div>
          <span className="deploy-kicker">{app.environment} application</span>
          <h2>{app.name}</h2>
          <p>
            <Code2 />
            {app.repo.url} <span>·</span> {app.repo.branch}
          </p>
        </div>
        <div className="deploy-hero-actions">
          <Button variant="outline" onClick={onEdit}>
            <Pencil />
            Edit
          </Button>
          <Button variant="destructive" onClick={onDelete}>
            <Trash2 />
            Delete
          </Button>
        </div>
      </header>

      <div className="deploy-summary-strip">
        <div>
          <span>Status</span>
          <strong className={`deploy-status status-${displayStatus}`}>
            <i />
            {runLabel(displayStatus)}
          </strong>
        </div>
        <div>
          <span>Runtime</span>
          <strong>
            {app.runtime.type} · Node {app.runtime.node_version}
          </strong>
        </div>
        <div>
          <span>Destination</span>
          <strong>{app.folder}</strong>
        </div>
        <div>
          <span>Last deploy</span>
          <strong>{latest ? new Date(latest.started_at_ms).toLocaleString() : "Never"}</strong>
        </div>
      </div>

      {latest?.status === "done" && (
        <section className="deploy-live-card">
          <div className="deploy-live-icon">
            <CheckCircle2 />
          </div>
          <div>
            <span>Live</span>
            <strong>{publicUrl ?? "Deployment completed"}</strong>
            <p>Commit {latest.commit?.slice(0, 10) || "recorded"} is running on this server.</p>
          </div>
          <div>
            {publicUrl && (
              <Button variant="outline" onClick={() => window.open(publicUrl, "_blank", "noopener,noreferrer")}>
                <ExternalLink />
                Open site
              </Button>
            )}
            <Button
              variant="outline"
              onClick={() => document.getElementById("deploy-run-history")?.scrollIntoView({ behavior: "smooth" })}
            >
              <History />
              View logs
            </Button>
          </div>
        </section>
      )}

      <section id="deploy-run-history" className="deploy-panel">
        <div className="deploy-panel-heading">
          <div>
            <span className="deploy-kicker">History</span>
            <h3>Recent deployments</h3>
          </div>
          <Button size="sm" variant="ghost" onClick={onRefreshHistory}>
            <RefreshCw />
            Refresh
          </Button>
        </div>
        {history.length ? (
          <div className="deploy-history">
            {history.map((entry) => (
              <details key={entry.id}>
                <summary>
                  <span className={`deploy-history-state status-${entry.status}`}>
                    <i />
                    {runLabel(entry.status)}
                  </span>
                  <strong>{entry.action}</strong>
                  <time>{new Date(entry.started_at_ms).toLocaleString()}</time>
                  <code>{entry.commit?.slice(0, 10) || "—"}</code>
                </summary>
                {entry.output && <pre>{entry.output}</pre>}
              </details>
            ))}
          </div>
        ) : (
          <div className="deploy-preflight-placeholder">
            <History />
            <div>
              <strong>No deployments yet</strong>
              <span>The first completed run will appear here.</span>
            </div>
          </div>
        )}
      </section>
    </>
  );
}
