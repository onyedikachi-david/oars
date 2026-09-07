import { KeyRound, LoaderCircle, Play, ShieldCheck } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { approvalIds } from "../../../deploy-state";
import type { DeployApp, DeployPreflight } from "../../../types";
import { PreflightApprovals } from "./PreflightApprovals";
import { PreflightIssues } from "./PreflightIssues";
import { PreflightPlanList } from "./PreflightPlanList";
import { PreflightSecretInputs } from "./PreflightSecretInputs";

export interface PreflightInspectorProps {
  app: DeployApp;
  preflight: DeployPreflight | null;
  preflightBusy: boolean;
  repoActionBusy: boolean;
  deployPublicKey: string;
  approvals: Record<string, boolean>;
  secretInputs: Record<string, string>;
  isRunActive: boolean;
  onStartPreflight: () => void;
  onCancelPreflight: () => void;
  onCreateDeployKey: () => void;
  onTrustGitHost: () => void;
  onToggleApproval: (id: string, checked: boolean) => void;
  onChangeSecret: (name: string, value: string) => void;
  onStartRun: () => void;
}

export function PreflightInspector({
  app,
  preflight,
  preflightBusy,
  repoActionBusy,
  deployPublicKey,
  approvals,
  secretInputs,
  isRunActive,
  onStartPreflight,
  onCancelPreflight,
  onCreateDeployKey,
  onTrustGitHost,
  onToggleApproval,
  onChangeSecret,
  onStartRun,
}: PreflightInspectorProps) {
  return (
    <section className="deploy-panel">
      <div className="deploy-panel-heading">
        <div>
          <span className="deploy-kicker">Safety review</span>
          <h3>Preflight and deployment plan</h3>
          <p>Oars reads the server first, then freezes the exact commands and file changes for approval.</p>
        </div>
        <Button onClick={onStartPreflight} disabled={preflightBusy || isRunActive}>
          {preflightBusy ? (
            <>
              <LoaderCircle className="is-spinning" />
              Checking server
            </>
          ) : (
            <>
              <ShieldCheck />
              {preflight ? "Check again" : "Run preflight"}
            </>
          )}
        </Button>
      </div>

      {!preflight ? (
        <div className="deploy-preflight-placeholder">
          <ShieldCheck />
          <div>
            <strong>No reviewed plan yet</strong>
            <span>
              Preflight does not change the application or services. For a fresh repository, it removes its temporary
              inspection checkout when the check ends.
            </span>
          </div>
        </div>
      ) : (
        <div className="deploy-preflight" aria-live="polite">
          <div className="deploy-preflight-state">
            <strong>
              {preflight.status === "gathering"
                ? "Reading server state"
                : preflight.status === "ready"
                  ? "Ready for approval"
                  : preflight.status === "blocked"
                    ? "Deployment blocked"
                    : "Preflight failed"}
            </strong>
            <span>
              {preflight.facts.os || "Waiting for facts"} · {preflight.facts.arch || "—"} ·{" "}
              {preflight.facts.privilege || "—"}
              {preflight.facts.ports ? ` · ${preflight.facts.ports}` : ""}
            </span>
            <Button size="sm" variant="ghost" onClick={onCancelPreflight}>
              Clear review
            </Button>
          </div>

          <PreflightIssues
            preflight={preflight}
            repoActionBusy={repoActionBusy}
            deployPublicKey={deployPublicKey}
            onCreateDeployKey={onCreateDeployKey}
          />

          {preflight.facts.git_host_fingerprints && (
            <details className="deploy-trust-details">
              <summary>
                <KeyRound />
                Git host fingerprints
              </summary>
              <p>Compare these SHA-256 fingerprints with a trusted source for the Git host before you approve first use.</p>
              <pre>{preflight.facts.git_host_fingerprints}</pre>
            </details>
          )}

          <PreflightPlanList steps={preflight.steps} />

          {(preflight.configs.env || preflight.configs.pm2 || preflight.configs.nginx) && (
            <div className="deploy-config-previews">
              <strong>Reviewed file previews</strong>
              {(
                [
                  ["Environment file", preflight.configs.env],
                  ["PM2 ecosystem", preflight.configs.pm2],
                  ["Nginx site", preflight.configs.nginx],
                ] as const
              )
                .filter(([, value]) => value)
                .map(([label, value]) => (
                  <details key={label}>
                    <summary>{label}</summary>
                    <pre>{value}</pre>
                  </details>
                ))}
            </div>
          )}

          <PreflightApprovals
            approvalsList={preflight.approvals}
            approvals={approvals}
            repoActionBusy={repoActionBusy}
            onToggleApproval={onToggleApproval}
            onTrustGitHost={onTrustGitHost}
          />

          <PreflightSecretInputs app={app} secretInputs={secretInputs} onChangeSecret={onChangeSecret} />

          <div className="deploy-commit-row">
            <p>
              {preflight.commit
                ? `Frozen commit ${preflight.commit.slice(0, 12)}`
                : "The repository commit must be resolved before deployment."}
            </p>
            <Button
              onClick={onStartRun}
              disabled={
                preflight.status !== "ready" ||
                preflight.blockers.length > 0 ||
                approvalIds(preflight).some((id) => !approvals[id])
              }
            >
              <Play />
              Deploy reviewed plan
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
