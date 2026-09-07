import { AlertTriangle, KeyRound, LoaderCircle } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { DeployPreflight } from "../../../types";

export interface PreflightIssuesProps {
  preflight: DeployPreflight;
  repoActionBusy: boolean;
  deployPublicKey: string;
  onCreateDeployKey: () => void;
}

export function PreflightIssues({
  preflight,
  repoActionBusy,
  deployPublicKey,
  onCreateDeployKey,
}: PreflightIssuesProps) {
  return (
    <>
      {(preflight.error || preflight.blockers.length > 0) && (
        <div className="deploy-issues is-blocked">
          <AlertTriangle />
          <div>
            <strong>{preflight.error ? "Preflight could not finish" : "Resolve before deployment"}</strong>
            {preflight.error && <p>{preflight.error}</p>}
            {preflight.blockers.map((issue) => (
              <p key={issue.id}>{issue.message}</p>
            ))}
          </div>
        </div>
      )}

      {preflight.blockers.some((issue) => issue.id === "missing_deploy_key") && (
        <div className="deploy-recovery-card">
          <KeyRound />
          <div>
            <strong>Create this application’s deploy key</strong>
            <p>Add the public key to the repository with read access, then run preflight again.</p>
          </div>
          <Button variant="outline" disabled={repoActionBusy} onClick={onCreateDeployKey}>
            {repoActionBusy ? <LoaderCircle className="is-spinning" /> : <KeyRound />}
            Create key
          </Button>
        </div>
      )}

      {deployPublicKey && (
        <div className="deploy-public-key">
          <div>
            <strong>Repository deploy key</strong>
            <p>Add this public key to the repository with read access. Oars keeps the private key on this server.</p>
          </div>
          <pre>{deployPublicKey}</pre>
          <Button size="sm" variant="outline" onClick={() => void navigator.clipboard.writeText(deployPublicKey)}>
            Copy public key
          </Button>
        </div>
      )}

      {preflight.warnings.length > 0 && (
        <div className="deploy-issues">
          <AlertTriangle />
          <div>
            <strong>Review these limits</strong>
            {preflight.warnings.map((issue) => (
              <p key={issue.id}>{issue.message}</p>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
