import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../../bridge";
import type { DeployApp, DeployHistoryRecord } from "../../../types";
import { messageOf, terminalStatuses } from "../utils";

export function useDeployList(
  serverId: string,
  initialAppId?: string | null,
  onAppsLoaded?: (apps: DeployApp[]) => void,
  onClearPendingApp?: () => void,
  runId?: number | null,
  runAppId?: string | null,
  runStatus?: string,
  resetRun?: () => void,
) {
  const [apps, setApps] = useState<DeployApp[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [history, setHistory] = useState<DeployHistoryRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(
    () => apps.find((app) => app.id === selectedId) ?? apps[0] ?? null,
    [apps, selectedId],
  );

  const loadHistory = useCallback(
    async (appId: string) => {
      try {
        const response = await api.deploy.history(serverId, appId, 10);
        setHistory(response.runs ?? []);
      } catch (cause) {
        setError(messageOf(cause));
      }
    },
    [serverId],
  );

  const onAppsLoadedRef = useRef(onAppsLoaded);
  onAppsLoadedRef.current = onAppsLoaded;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.deploy.list(serverId);
      setApps(response.apps);
      onAppsLoadedRef.current?.(response.apps);
      setSelectedId((current) =>
        response.apps.some((app) => app.id === current) ? current : response.apps[0]?.id ?? null,
      );
      setError(null);
    } catch (cause) {
      setError(messageOf(cause));
    } finally {
      setLoading(false);
      setHasLoaded(true);
    }
  }, [serverId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (initialAppId && apps.some((app) => app.id === initialAppId)) {
      setSelectedId(initialAppId);
      onClearPendingApp?.();
    }
  }, [initialAppId, apps, onClearPendingApp]);

  useEffect(() => {
    setHistory([]);
    if (selected) void loadHistory(selected.id);
  }, [selected?.id, loadHistory]);

  const selectApp = (appId: string) => {
    if (runId != null && runAppId !== appId && runStatus && !terminalStatuses.has(runStatus)) {
      setError(
        "A deployment is still active. Wait for it to finish or request cancellation before opening another application.",
      );
      return;
    }
    if (runId != null && runAppId !== appId) resetRun?.();
    setSelectedId(appId);
  };

  return {
    apps,
    selectedId,
    setSelectedId,
    selected,
    history,
    loading,
    hasLoaded,
    error,
    setError,
    load,
    loadHistory,
    selectApp,
  };
}
