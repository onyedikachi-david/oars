import { describe, expect, it, vi, beforeEach } from "vitest";
import { BridgeError, api } from "../../bridge";
import type { DeployApp } from "../../types";
import {
  terminalStatuses,
  account,
  messageOf,
  wait,
  cloneApp,
  emptyEditor,
  waitForSshCommand,
} from "./utils";

describe("features/deploy/utils", () => {
  describe("terminalStatuses", () => {
    it("contains all terminal deploy status strings", () => {
      expect(terminalStatuses.has("done")).toBe(true);
      expect(terminalStatuses.has("failed")).toBe(true);
      expect(terminalStatuses.has("canceled")).toBe(true);
      expect(terminalStatuses.has("interrupted")).toBe(true);
      expect(terminalStatuses.has("running")).toBe(false);
      expect(terminalStatuses.has("queued")).toBe(false);
    });
  });

  describe("account", () => {
    it("generates vault credential key for deploy app environment variable", () => {
      expect(account("app-123", "DATABASE_URL")).toBe("deploy:app-123:DATABASE_URL");
    });
  });

  describe("messageOf", () => {
    it("handles BridgeError, Error, and primitives", () => {
      expect(messageOf(new BridgeError("auth_failed", "Access denied"))).toBe("Access denied");
      expect(messageOf(new Error("Network disconnect"))).toBe("Network disconnect");
      expect(messageOf("Direct error text")).toBe("Direct error text");
      expect(messageOf(500)).toBe("500");
    });
  });

  describe("wait", () => {
    it("resolves after timeout", async () => {
      const start = Date.now();
      await wait(10);
      expect(Date.now() - start).toBeGreaterThanOrEqual(5);
    });
  });

  describe("cloneApp", () => {
    it("deep clones app configurations including nested objects and arrays", () => {
      const original: any = {
        id: "app-1",
        name: "My App",
        server_id: "srv-1",
        repo: {
          url: "git@github.com:org/repo.git",
          branch: "main",
          path: "/srv/app",
          auto_trust_host: true,
        },
        runtime: {
          type: "node",
          version: "20.x",
          build_command: "npm run build",
          start_command: "npm start",
          port: 3000,
        },
        env_vars: [{ name: "ENV", value: "prod", secret: false }],
        service: {
          name: "app",
          service_type: "systemd",
          restart_policy: "always",
        },
        domains: ["app.example.com"],
        created_at: 1700000000000,
        updated_at: 1700000000000,
      };

      const cloned = cloneApp(original);
      expect(cloned).toEqual(original);
      expect(cloned).not.toBe(original);
      expect(cloned.repo).not.toBe(original.repo);
      expect(cloned.runtime).not.toBe(original.runtime);
      expect(cloned.domains).not.toBe(original.domains);

      // Verify array mutation safety
      cloned.domains.push("new.example.com");
      expect(original.domains).toHaveLength(1);
    });

    it("handles empty or missing env_vars and domains gracefully", () => {
      const partial = {
        id: "app-2",
        name: "Partial",
        server_id: "srv-1",
        repo: { url: "" },
        runtime: {},
      } as any;

      const cloned = cloneApp(partial);
      expect(cloned.env_vars).toEqual([]);
      expect(cloned.domains).toEqual([]);
    });
  });

  describe("emptyEditor", () => {
    it("creates a clean default EditorState template for a given serverId", () => {
      const editor = emptyEditor("srv-target");
      expect(editor.server_id).toBe("srv-target");
      expect(editor.environment).toBe("production");
      expect(editor.app_port).toBe(3000);
      expect(editor.repo.branch).toBe("main");
      expect(editor.runtime.type).toBe("next");
      expect(editor.env_vars).toEqual([]);
      expect(editor.domains).toEqual([]);
    });
  });

  describe("waitForSshCommand", () => {
    beforeEach(() => {
      vi.restoreAllMocks();
    });

    it("resolves with full output when channel hits EOF with exit code 0", async () => {
      let pollCount = 0;
      vi.spyOn(api.ssh, "poll").mockImplementation(async () => {
        pollCount++;
        if (pollCount === 1) {
          return {
            channels: [{ id: 42, data: "Building step 1...\n", cursor: 20, eof: false }],
            closed: [],
          } as any;
        }
        return {
          channels: [{ id: 42, data: "Build complete!\n", cursor: 36, eof: true, exit: 0 }],
          closed: [],
        } as any;
      });

      const closeSpy = vi.spyOn(api.ssh, "closeChannel").mockResolvedValue({ ok: true } as any);

      const output = await waitForSshCommand("srv-1", 42);
      expect(output).toBe("Building step 1...\nBuild complete!\n");
      expect(closeSpy).toHaveBeenCalledWith("srv-1", 42);
    });

    it("throws error when command exits with non-zero exit code", async () => {
      vi.spyOn(api.ssh, "poll").mockResolvedValue({
        channels: [{ id: 42, data: "error: exit status 1\n", cursor: 22, eof: true, exit: 1 }],
        closed: [],
      } as any);

      const closeSpy = vi.spyOn(api.ssh, "closeChannel").mockResolvedValue({ ok: true } as any);

      await expect(waitForSshCommand("srv-1", 42)).rejects.toThrow("error: exit status 1");
      expect(closeSpy).toHaveBeenCalledWith("srv-1", 42);
    });

    it("throws error when channel is missing for 8 consecutive polls", async () => {
      vi.spyOn(api.ssh, "poll").mockResolvedValue({
        channels: [],
        closed: [],
      } as any);

      const closeSpy = vi.spyOn(api.ssh, "closeChannel").mockResolvedValue({ ok: true } as any);

      await expect(waitForSshCommand("srv-1", 42)).rejects.toThrow("The SSH command output was not available.");
      expect(closeSpy).toHaveBeenCalledWith("srv-1", 42);
    });
  });
});
