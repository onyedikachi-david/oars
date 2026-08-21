import { LoaderCircle, ShieldCheck } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { DeployApproval } from "../../../types";

export interface PreflightApprovalsProps {
  approvalsList: DeployApproval[];
  approvals: Record<string, boolean>;
  repoActionBusy: boolean;
  onToggleApproval: (id: string, checked: boolean) => void;
  onTrustGitHost: () => void;
}

export function PreflightApprovals({
  approvalsList,
  approvals,
  repoActionBusy,
  onToggleApproval,
  onTrustGitHost,
}: PreflightApprovalsProps) {
  return (
    <>
      {approvalsList.length > 0 && (
        <div className="deploy-approvals">
          <strong>Required approvals</strong>
          {approvalsList.map((approval) => (
            <label key={approval.id}>
              <input
                type="checkbox"
                checked={approvals[approval.id] ?? false}
                onChange={(event) => onToggleApproval(approval.id, event.target.checked)}
              />
              <span>
                <b>{approval.label}</b>
                <small>{approval.detail}</small>
              </span>
            </label>
          ))}
        </div>
      )}

      {approvalsList.some((approval) => approval.id === "git-host-key") && (
        <div className="deploy-host-trust-action">
          <p>
            This writes only the approved key to this application’s private known-hosts file. Preflight then checks
            repository access again.
          </p>
          <Button
            variant="outline"
            disabled={repoActionBusy || !approvals["git-host-key"]}
            onClick={onTrustGitHost}
          >
            {repoActionBusy ? <LoaderCircle className="is-spinning" /> : <ShieldCheck />}
            Trust host and check again
          </Button>
        </div>
      )}
    </>
  );
}
