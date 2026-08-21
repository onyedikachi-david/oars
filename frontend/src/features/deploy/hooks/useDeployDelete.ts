import { useState } from "react";
import { api, vault } from "../../../bridge";
import type { DeployApp } from "../../../types";
import type { DeleteState } from "../types";
import { account, messageOf } from "../utils";

export function useDeployDelete(serverId: string, onDeleted: () => Promise<void>) {
  const [deleteState, setDeleteState] = useState<DeleteState | null>(null);

  const openDelete = (app: DeployApp) => setDeleteState({ app, busy: false, error: null });
  const closeDelete = () => {
    if (!deleteState?.busy) setDeleteState(null);
  };

  const confirmDelete = async () => {
    if (!deleteState) return;
    const app = deleteState.app;
    setDeleteState({ ...deleteState, busy: true, error: null });
    const snapshots = new Map<string, string>();
    const removed: string[] = [];
    try {
      for (const row of app.env_vars.filter((item) => item.secret && item.has_value)) {
        const value = await vault.deployTransientGet(account(app.id, row.name));
        if (value == null) throw new Error(`The stored value for ${row.name} could not be read.`);
        snapshots.set(row.name, value);
      }
      for (const name of snapshots.keys()) {
        await vault.delete(account(app.id, name));
        removed.push(name);
      }
      await api.deploy.remove(serverId, app.id);
      setDeleteState(null);
      await onDeleted();
    } catch (cause) {
      for (const name of removed) {
        const value = snapshots.get(name);
        if (value != null) await vault.set(account(app.id, name), value).catch(() => undefined);
      }
      setDeleteState({ app, busy: false, error: `${messageOf(cause)} The app was not deleted.` });
    }
  };

  return { deleteState, openDelete, closeDelete, confirmDelete };
}
