import { useCallback, useEffect, useRef, useState } from "react";
import { api, BridgeError, vault } from "../../../bridge";
import { appendDeployOutput, approvalIds, cursorsFromSteps } from "../../../deploy-state";
import type { DeployApp, DeployPollResult, DeployPreflight, DeployStep } from "../../../types";

const terminalStatuses = new Set(["done", "failed", "canceled", "interrupted"]);
const account = (appId: string, name: string) => `deploy:${appId}:${name}`;
const messageOf = (error: unknown) =>
  error instanceof BridgeError ? error.message : error instanceof Error ? error.message : String(error);

export interface UseDeployRunReturn {
  runId: number | null;
  runAppId: string | null;
  runStatus: string;
  steps: DeployStep[];
  outputs: Record<string, string>;
  gaps: Record<string, boolean>;
  startRun: (
    selected: DeployApp,
    preflight: DeployPreflight,
    approvals: Record<string, boolean>,
    secretInputs: Record<string, string>,
  ) => Promise<void>;
  requestCancel: () => Promise<void>;
  resetRun: () => void;
}

export function useDeployRun(
  serverId: string,
  onRunComplete?: (appId: string) => void,
  onError?: (error: string) => void,
): UseDeployRunReturn {
  const [runId, setRunId] = useState<number | null>(null);
  const [runAppId, setRunAppId] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState<string>("");
  const [steps, setSteps] = useState<DeployStep[]>([]);
  const [outputs, setOutputs] = useState<Record<string, string>>({});
  const [gaps, setGaps] = useState<Record<string, boolean>>({});

  const pollGeneration = useRef(0);
  const cursorsRef = useRef<Record<string, number>>({});
  const outputRef = useRef<Record<string, string>>({});
  const gapsRef = useRef<Record<string, boolean>>({});

  const resetRun = useCallback(() => {
    pollGeneration.current += 1;
    setRunId(null);
    setRunAppId(null);
    setRunStatus("");
    setSteps([]);
    setOutputs({});
    setGaps({});
    cursorsRef.current = {};
    outputRef.current = {};
    gapsRef.current = {};
  }, []);

  const requestCancel = useCallback(async () => {
    if (runId == null) return;
    try {
      await api.deploy.cancel(runId);
      setRunStatus("cancel_requested");
    } catch (cause) {
      onError?.(messageOf(cause));
    }
  }, [runId, onError]);

  const startRun = useCallback(
    async (
      selected: DeployApp,
      preflight: DeployPreflight,
      approvals: Record<string, boolean>,
      secretInputs: Record<string, string>,
    ) => {
      if (!selected || !preflight || preflight.status !== "ready") return;
      const required = approvalIds(preflight);
      if (required.some((id) => !approvals[id])) {
        onError?.("Approve every required change before deployment.");
        return;
      }
      const values: Array<{ name: string; value: string }> = [];
      try {
        for (const row of selected.env_vars.filter((item) => item.secret)) {
          const typed = secretInputs[row.name];
          const value = typed || (await vault.deployTransientGet(account(selected.id, row.name)));
          if (!value) throw new Error(`Enter or store a value for ${row.name}.`);
          values.push({ name: row.name, value });
          await vault.transientForget(account(selected.id, row.name));
        }
        const response = await api.deploy.run({
          preflight_id: preflight.id,
          approvals: required,
          secret_values: values,
        });
        cursorsRef.current = {};
        outputRef.current = {};
        gapsRef.current = {};
        setOutputs({});
        setGaps({});
        setSteps([]);
        setRunStatus("queued");
        setRunAppId(selected.id);
        setRunId(response.run_id);
      } catch (cause) {
        onError?.(messageOf(cause));
      }
    },
    [onError],
  );

  useEffect(() => {
    if (runId == null) return;
    const generation = ++pollGeneration.current;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const result: DeployPollResult = await api.deploy.poll(runId, cursorsRef.current);
        if (generation !== pollGeneration.current) return;
        setRunStatus(result.status);
        setSteps(result.steps);
        cursorsRef.current = { ...cursorsRef.current, ...cursorsFromSteps(result.steps) };
        const nextOutputs = { ...outputRef.current };
        const nextGaps = { ...gapsRef.current };
        for (const step of result.steps) {
          const appended = appendDeployOutput(
            nextOutputs[step.id] ?? "",
            step.data,
            step.gap,
            nextGaps[step.id] ?? false,
          );
          nextOutputs[step.id] = appended.text;
          nextGaps[step.id] = appended.gapNoted;
        }
        outputRef.current = nextOutputs;
        gapsRef.current = nextGaps;
        setOutputs(nextOutputs);
        setGaps(nextGaps);
        if (result.done) {
          if (runAppId) onRunComplete?.(runAppId);
          return;
        }
        timer = window.setTimeout(poll, 800);
      } catch (cause) {
        if (generation !== pollGeneration.current) return;
        onError?.(`${messageOf(cause)} Retrying deployment status…`);
        timer = window.setTimeout(poll, 1600);
      }
    };

    void poll();
    return () => {
      pollGeneration.current += 1;
      if (timer) window.clearTimeout(timer);
    };
  }, [runId, runAppId, onRunComplete, onError]);

  return {
    runId,
    runAppId,
    runStatus,
    steps,
    outputs,
    gaps,
    startRun,
    requestCancel,
    resetRun,
  };
}
