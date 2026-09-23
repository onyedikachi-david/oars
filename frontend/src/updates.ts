import { useEffect, useState } from "react";
import { invoke } from "./bridge";
export interface UpdateStatus {
  mode: "unavailable" | "sparkle" | "homebrew" | "manual";
  state: "unavailable" | "idle" | "checking" | "available" | "downloading" | "verifying" | "ready" | "blocked" | "error";
  current_version: string;
  latest_version: string;
  error: string;
  automatic_checks: boolean;
  automatic_downloads: boolean;
  can_check: boolean;
  can_resume: boolean;
  busy: boolean;
}
export const updateApi = {
  status: () => invoke<UpdateStatus>("oars.updates.status"),
  check: () => invoke("oars.updates.check"),
  preferences: (automatic_checks: boolean, automatic_downloads: boolean) => invoke("oars.updates.preferences", { automatic_checks, automatic_downloads }),
  resume: () => invoke("oars.updates.resume"),
  releaseNotes: () => invoke("oars.updates.releaseNotes"),
};
export function useUpdates(interval = 2000) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  useEffect(() => {
    if (!window.zero) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const next = await updateApi.status();
        if (!stopped && next && typeof next.current_version === "string") setStatus(next);
      } catch { /* Older app versions do not expose the updater bridge. */ }
      finally { if (!stopped) timer = setTimeout(() => void poll(), interval); }
    };
    void poll();
    return () => { stopped = true; clearTimeout(timer); };
  }, [interval]);
  return status;
}
