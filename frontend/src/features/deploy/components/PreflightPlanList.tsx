import { RefreshCw, ShieldCheck } from "lucide-react";
import type { DeployPreflight } from "../../../types";

export interface PreflightPlanListProps {
  steps: DeployPreflight["steps"];
}

export function PreflightPlanList({ steps }: PreflightPlanListProps) {
  return (
    <div className="deploy-plan-list">
      {steps.map((step, index) => (
        <details key={step.id} className="deploy-plan-step">
          <summary>
            <span>{index + 1}</span>
            <div>
              <strong>{step.label}</strong>
              <small>{step.skipped ? "Skipped" : step.mutation}</small>
            </div>
            <code>{step.files[0]?.path ?? "remote command"}</code>
          </summary>
          {!step.skipped && (
            <div>
              <pre>{step.command}</pre>
              {step.guards.map((guard) => (
                <p key={guard}>
                  <ShieldCheck />
                  {guard}
                </p>
              ))}
              {step.rollback && (
                <p>
                  <RefreshCw />
                  {step.rollback}
                </p>
              )}
            </div>
          )}
        </details>
      ))}
    </div>
  );
}
