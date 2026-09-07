import { CheckCircle2, Clock3, LoaderCircle, X, XCircle } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { DeployStep } from "../../../types";
import { runLabel } from "./DeployDetailView";

const terminalStatuses = new Set(["done", "failed", "canceled", "interrupted"]);

export interface DeployOutputPaneProps {
  runId: number;
  runStatus: string;
  steps: DeployStep[];
  outputs: Record<string, string>;
  gaps: Record<string, boolean>;
  onCancel: () => void;
  onClose: () => void;
}

export function DeployOutputPane({
  runId,
  runStatus,
  steps,
  outputs,
  gaps,
  onCancel,
  onClose,
}: DeployOutputPaneProps) {
  const isTerminal = terminalStatuses.has(runStatus);

  return (
    <section className="deploy-panel deploy-run" aria-live="polite">
      <div className="deploy-panel-heading">
        <div>
          <span className="deploy-kicker">Run #{runId}</span>
          <h3>{runLabel(runStatus)}</h3>
        </div>
        {!isTerminal && (
          <Button variant="destructive" onClick={onCancel}>
            <X />
            Request cancel
          </Button>
        )}
      </div>
      <div className="deploy-run-steps">
        {steps.map((step) => (
          <div key={step.id} className={`deploy-run-step state-${step.state}`}>
            <span className="deploy-run-state">
              {step.state === "success" ? (
                <CheckCircle2 />
              ) : step.state === "failed" ? (
                <XCircle />
              ) : step.state === "running" ? (
                <LoaderCircle className="is-spinning" />
              ) : (
                <Clock3 />
              )}
            </span>
            <div>
              <strong>{step.label}</strong>
              <small>
                {step.error || step.state}
                {step.exit != null ? ` · exit ${step.exit}` : ""}
              </small>
              {gaps[step.id] && <p className="deploy-gap">Earlier output was dropped before this view read it.</p>}
              {outputs[step.id] && (
                <pre role="log" aria-live="polite" aria-atomic="false" tabIndex={0} aria-label={`Output for ${step.label}`}>
                  {outputs[step.id]}
                </pre>
              )}
            </div>
          </div>
        ))}
      </div>
      {isTerminal && (
        <Button variant="outline" onClick={onClose}>
          Close run
        </Button>
      )}
    </section>
  );
}
