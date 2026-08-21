import { KeyRound } from "lucide-react";
import type { DeployApp } from "../../../types";

export interface PreflightSecretInputsProps {
  app: DeployApp;
  secretInputs: Record<string, string>;
  onChangeSecret: (name: string, value: string) => void;
}

export function PreflightSecretInputs({ app, secretInputs, onChangeSecret }: PreflightSecretInputsProps) {
  if (!app.env_vars.some((row) => row.secret)) return null;

  return (
    <div className="deploy-secret-grid">
      <div>
        <KeyRound />
        <span>
          <strong>Deployment secrets</strong>
          <small>Use stored Keychain values or enter a value for this run.</small>
        </span>
      </div>
      {app.env_vars
        .filter((row) => row.secret)
        .map((row) => (
          <label key={row.name} htmlFor={`deploy-secret-${row.name}`}>
            <span>{row.name}</span>
            <input
              id={`deploy-secret-${row.name}`}
              type="password"
              autoComplete="off"
              placeholder={row.has_value ? "Stored — leave blank to reuse" : "Required value"}
              value={secretInputs[row.name] ?? ""}
              onChange={(event) => onChangeSecret(row.name, event.target.value)}
            />
          </label>
        ))}
    </div>
  );
}
