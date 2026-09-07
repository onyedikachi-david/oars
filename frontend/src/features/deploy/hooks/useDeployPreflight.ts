import { useEffect, useRef, useState } from "react";
import { api } from "../../../bridge";
import type { DeployApp, DeployPreflight } from "../../../types";
import { messageOf, waitForSshCommand } from "../utils";

export function useDeployPreflight(
  serverId: string,
  selected: DeployApp | null,
  onError: (error: string | null) => void,
) {
  const [preflight, setPreflight] = useState<DeployPreflight | null>(null);
  const [preflightBusy, setPreflightBusy] = useState(false);
  const [repoActionBusy, setRepoActionBusy] = useState(false);
  const [deployPublicKey, setDeployPublicKey] = useState("");
  const [approvals, setApprovals] = useState<Record<string, boolean>>({});
  const [secretInputs, setSecretInputs] = useState<Record<string, string>>({});

  const preflightGeneration = useRef(0);
  const preflightIdRef = useRef<number | null>(null);

  useEffect(() => {
    preflightGeneration.current += 1;
    const preflightId = preflightIdRef.current;
    preflightIdRef.current = null;
    if (preflightId != null) void api.deploy.preflightCancel(preflightId).catch(() => undefined);
    setPreflightBusy(false);
    setPreflight(null);
    setApprovals({});
    setSecretInputs({});
    setDeployPublicKey("");
  }, [selected?.id]);

  useEffect(() => {
    return () => {
      preflightGeneration.current += 1;
      const preflightId = preflightIdRef.current;
      preflightIdRef.current = null;
      if (preflightId != null) void api.deploy.preflightCancel(preflightId).catch(() => undefined);
    };
  }, []);

  const startPreflight = async () => {
    if (!selected) return;
    const generation = ++preflightGeneration.current;
    setPreflightBusy(true);
    setPreflight(null);
    setApprovals({});
    onError(null);
    try {
      const previous = preflightIdRef.current;
      preflightIdRef.current = null;
      if (previous != null) await api.deploy.preflightCancel(previous).catch(() => undefined);
      if (generation !== preflightGeneration.current) return;
      let current = (await api.deploy.preflight(serverId, selected.id)).preflight;
      if (generation !== preflightGeneration.current) return;
      preflightIdRef.current = current.id;
      setPreflight(current);
      while (current.status === "gathering") {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        if (generation !== preflightGeneration.current) return;
        current = (await api.deploy.preflightPoll(current.id)).preflight;
        setPreflight(current);
      }
    } catch (cause) {
      if (generation === preflightGeneration.current) onError(messageOf(cause));
    } finally {
      if (generation === preflightGeneration.current) setPreflightBusy(false);
    }
  };

  const cancelPreflight = async () => {
    const currentId = preflightIdRef.current ?? preflight?.id ?? null;
    preflightIdRef.current = null;
    preflightGeneration.current += 1;
    setPreflightBusy(false);
    setPreflight(null);
    setApprovals({});
    if (currentId != null) await api.deploy.preflightCancel(currentId).catch(() => undefined);
  };

  const createDeployKey = async () => {
    if (!selected) return;
    setRepoActionBusy(true);
    onError(null);
    try {
      const response = await api.deploy.keyGenerate(serverId, selected.id);
      const output = await waitForSshCommand(serverId, response.channel);
      const marker = output.indexOf("@public\n");
      const publicKey = marker >= 0 ? output.slice(marker + 8).trim().split("\n", 1)[0] : "";
      if (!publicKey.startsWith("ssh-ed25519 ")) throw new Error("The deploy public key response was invalid.");
      setDeployPublicKey(publicKey);
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setRepoActionBusy(false);
    }
  };

  const trustGitHost = async () => {
    if (!preflight || !approvals["git-host-key"]) return;
    setRepoActionBusy(true);
    onError(null);
    try {
      const response = await api.deploy.hostTrust(preflight.id);
      await waitForSshCommand(serverId, response.channel);
      preflightIdRef.current = null;
      setPreflight(null);
      setApprovals({});
      await startPreflight();
    } catch (cause) {
      onError(messageOf(cause));
    } finally {
      setRepoActionBusy(false);
    }
  };

  return {
    preflight,
    preflightBusy,
    repoActionBusy,
    deployPublicKey,
    approvals,
    secretInputs,
    startPreflight,
    cancelPreflight,
    createDeployKey,
    trustGitHost,
    setApprovals,
    setSecretInputs,
  };
}
