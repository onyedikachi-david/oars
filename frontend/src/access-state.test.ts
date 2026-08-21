import { describe, expect, it } from "vitest";
import {
  grantKey,
  phaseLabel,
  defaultRoleAccountName,
  isValidLinuxAccountName,
  parseFingerprintsInput,
  validateIdentityInput,
  validateOnboardTargets,
  buildOnboardTargets,
  computeAccessStatusText,
  type OnboardTargetChoice,
} from "./access-state";
import type { AccessGrant, AccessServerView } from "./types";

describe("access-state pure model", () => {
  describe("grantKey", () => {
    it("formats grant key as server:user:path:hash", () => {
      const grant: AccessGrant = {
        server_id: "srv-1",
        server_name: "prod-server",
        user: "ubuntu",
        source_path: "/home/ubuntu/.ssh/authorized_keys",
        line_hash: "hash123",
        fingerprint: "SHA256:abc",
        comment: "test-key",
        sudo: "full",
        file_sha256: "sha256_placeholder",
      };
      expect(grantKey(grant)).toBe("srv-1:ubuntu:/home/ubuntu/.ssh/authorized_keys:hash123");
    });
  });

  describe("phaseLabel", () => {
    it("maps internal scan phases to readable strings", () => {
      expect(phaseLabel("queued")).toBe("Queued");
      expect(phaseLabel("identity")).toBe("Reading account");
      expect(phaseLabel("sudo_probe")).toBe("Checking policy");
      expect(phaseLabel("enumerate")).toBe("Finding accounts");
      expect(phaseLabel("read_accounts")).toBe("Reading key sources");
      expect(phaseLabel("sshd_config")).toBe("Checking SSH policy");
      expect(phaseLabel("done")).toBe("Done");
      expect(phaseLabel("error")).toBe("Sync error");
      expect(phaseLabel("custom_phase")).toBe("custom_phase");
    });
  });

  describe("defaultRoleAccountName", () => {
    it("generates sanitized readonly role account names", () => {
      expect(defaultRoleAccountName("John Doe")).toBe("john-doe-readonly");
      expect(defaultRoleAccountName("Alice@Admin!")).toBe("alice-admin-readonly");
      expect(defaultRoleAccountName("---")).toBe("access-readonly");
      expect(defaultRoleAccountName("")).toBe("access-readonly");
      expect(defaultRoleAccountName("a".repeat(100))).toBe(`${"a".repeat(48)}-readonly`);
    });
  });

  describe("isValidLinuxAccountName", () => {
    it("validates Linux account naming rules", () => {
      expect(isValidLinuxAccountName("ubuntu")).toBe(true);
      expect(isValidLinuxAccountName("root")).toBe(true);
      expect(isValidLinuxAccountName("user_123")).toBe(true);
      expect(isValidLinuxAccountName("deploy-app")).toBe(true);
      expect(isValidLinuxAccountName("")).toBe(false);
      expect(isValidLinuxAccountName("-invalid")).toBe(false);
      expect(isValidLinuxAccountName("123user")).toBe(true); // [a-z0-9_] allows digits
      expect(isValidLinuxAccountName("user name")).toBe(false);
      expect(isValidLinuxAccountName("user@domain")).toBe(false);
    });
  });

  describe("parseFingerprintsInput", () => {
    it("parses newline and comma-separated fingerprints into clean arrays", () => {
      const input = "SHA256:abc123\n  SHA256:def456 , SHA256:ghi789\n\n";
      expect(parseFingerprintsInput(input)).toEqual([
        "SHA256:abc123",
        "SHA256:def456",
        "SHA256:ghi789",
      ]);
      expect(parseFingerprintsInput("")).toEqual([]);
    });
  });

  describe("validateIdentityInput", () => {
    it("validates non-empty name and fingerprint presence", () => {
      expect(validateIdentityInput("Alice", ["SHA256:abc"])).toEqual({ ok: true, error: null });
      expect(validateIdentityInput("", ["SHA256:abc"])).toEqual({
        ok: false,
        error: "Enter a name and at least one SHA-256 fingerprint.",
      });
      expect(validateIdentityInput("Alice", [])).toEqual({
        ok: false,
        error: "Enter a name and at least one SHA-256 fingerprint.",
      });
    });
  });

  describe("validateOnboardTargets", () => {
    it("ensures at least one enabled target with valid account name", () => {
      const validTarget: OnboardTargetChoice = {
        serverId: "s1",
        serverName: "prod",
        enabled: true,
        kind: "account",
        name: "deploy",
        accounts: ["deploy"],
      };

      expect(validateOnboardTargets([validTarget])).toEqual({ ok: true, error: null });

      const disabledTarget = { ...validTarget, enabled: false };
      expect(validateOnboardTargets([disabledTarget])).toEqual({
        ok: false,
        error: "Select at least one server target.",
      });

      const invalidNameTarget = { ...validTarget, name: "invalid name with spaces" };
      expect(validateOnboardTargets([invalidNameTarget])).toEqual({
        ok: false,
        error: "Each target needs a valid Linux account name.",
      });
    });
  });

  describe("buildOnboardTargets", () => {
    it("constructs target choices matching servers and existing grants", () => {
      const servers: AccessServerView[] = [
        {
          server_id: "s1",
          name: "web-01",
          host: "10.0.0.1",
          phase: "done",
          sudo: "full",
          coverage: "complete",
          connected_user: "admin",
          accounts: [
            { user: "admin", home: "/home/admin", skipped: false, read: true, sudo: "full", key_count: 1 },
            { user: "nobody", home: "/nonexistent", skipped: true, read: false, sudo: "none", key_count: 0 },
          ],
          sources: ["/home/admin/.ssh/authorized_keys"],
        },
      ];

      const grants: AccessGrant[] = [
        {
          server_id: "s1",
          server_name: "web-01",
          user: "ubuntu",
          source_path: "/home/ubuntu/.ssh/authorized_keys",
          line_hash: "h1",
          fingerprint: "SHA256:x",
          comment: "",
          sudo: "full",
          file_sha256: "sha256_placeholder",
        },
      ];

      const targets = buildOnboardTargets(servers, grants);
      expect(targets).toHaveLength(1);
      expect(targets[0].serverId).toBe("s1");
      expect(targets[0].enabled).toBe(true);
      expect(targets[0].name).toBe("ubuntu");
      expect(targets[0].accounts).toEqual(["admin"]);
    });
  });

  describe("computeAccessStatusText", () => {
    it("computes status string based on scope, state, and coverage", () => {
      expect(computeAccessStatusText(undefined, undefined, null)).toBe("No access snapshot");
      expect(computeAccessStatusText("all_login_accounts", "scanning", null)).toBe("Scanning · Full-account scope");
      expect(computeAccessStatusText("connected_accounts", "canceled", null)).toBe("Scan canceled · Connected-account scope");
      expect(computeAccessStatusText("connected_accounts", "done", "complete")).toBe("Connected-account scope · complete for this scope");
      expect(computeAccessStatusText("connected_accounts", "done", "partial")).toBe("Connected-account scope · partial coverage");
    });
  });
});
