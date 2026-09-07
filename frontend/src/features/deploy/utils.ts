import { api, BridgeError } from "../../bridge";
import type { DeployApp } from "../../types";
import type { EditorState } from "./types";

export const terminalStatuses = new Set(["done", "failed", "canceled", "interrupted"]);

export const account = (appId: string, name: string) => `deploy:${appId}:${name}`;

export const messageOf = (error: unknown): string =>
  error instanceof BridgeError ? error.message : error instanceof Error ? error.message : String(error);

export const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

export async function waitForSshCommand(serverId: string, channel: number): Promise<string> {
  let cursor = 0;
  let output = "";
  let missing = 0;
  try {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const result = await api.ssh.poll(serverId, [{ channel, cursor }], false);
      const current = result.channels.find((entry) => entry.id === channel);
      if (!current) {
        missing += 1;
        if (missing >= 8) throw new Error("The SSH command output was not available.");
        await wait(250);
        continue;
      }
      missing = 0;
      output += current.data;
      cursor = current.cursor;
      if (current.eof) {
        if (current.exit !== 0) {
          const detail = output.trim();
          throw new Error(detail || "The SSH command failed.");
        }
        return output;
      }
      await wait(250);
    }
    throw new Error("The SSH command timed out.");
  } finally {
    void api.ssh.closeChannel(serverId, channel).catch(() => undefined);
  }
}

export function cloneApp(app: DeployApp): EditorState {
  return {
    ...app,
    repo: { ...app.repo },
    runtime: { ...app.runtime },
    env_vars: Array.isArray(app.env_vars) ? app.env_vars.map((row) => ({ ...row })) : [],
    domains: Array.isArray(app.domains) ? [...app.domains] : [],
  };
}

export function emptyEditor(serverId: string): EditorState {
  return {
    server_id: serverId,
    name: "",
    environment: "production",
    folder: "",
    repo: { url: "", transport: "https", branch: "main" },
    runtime: {
      node_version: "24",
      type: "next",
      package_manager: "auto",
      install: "",
      build: "npm run build",
      entry: "node_modules/next/dist/bin/next",
      args: "start",
      start_command: "",
      build_folder: ".next",
    },
    env_vars: [],
    domains: [],
    ssl: false,
    email: "",
    app_port: 3000,
  };
}
