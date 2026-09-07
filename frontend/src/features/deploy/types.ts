import type { DeployApp, DeployAppInput } from "../../types";

export interface DeployTabProps {
  serverId: string;
  initialAppId?: string | null;
  onAppsLoaded?: (apps: DeployApp[]) => void;
  onClearPendingApp?: () => void;
}

export type EditorState = DeployAppInput & { id?: string };

export interface DeleteState {
  app: DeployApp;
  busy: boolean;
  error: string | null;
}
