import { describe, expect, it } from "vitest";
import {
  DEPLOY_OUTPUT_CAP,
  ENV_VALUE_LIMIT,
  appendDeployOutput,
  approvalIds,
  bulkImportEnv,
  cursorsFromSteps,
  describeMutation,
  formatHistoryTime,
  mergeImportedEnv,
  needsApproval,
  preflightBlockers,
  preflightWarnings,
} from "./deploy-state";

describe("bulkImportEnv", () => {
  it("preserves every byte after the first equals and defaults to secret", () => {
    const result = bulkImportEnv(' export TOKEN=  "a=b"  \nEMPTY=\n', []);
    expect(result.rows).toEqual([
      { name: "TOKEN", value: '  "a=b"  ', secret: true },
      { name: "EMPTY", value: "", secret: true },
    ]);
    expect(result.preview).toBe("TOKEN=••••••••\nEMPTY=••••••••");
  });

  it("handles CRLF line endings, comments, and lines without equals signs", () => {
    const input = "# Comment line\r\n  # Indented comment\r\nVALID=val\r\nINVALID_NO_EQUALS\r\n";
    const result = bulkImportEnv(input, []);
    expect(result.rows).toEqual([{ name: "VALID", value: "val", secret: true }]);
    expect(result.rejected).toEqual(["INVALID_NO_EQUALS\r"]);
  });

  it("rejects duplicate names instead of replacing an existing value", () => {
    const result = bulkImportEnv("API_KEY=new\nAPI_KEY=again", [{ name: "API_KEY", secret: true, value: "", has_value: true }]);
    expect(result.rows).toEqual([]);
    expect(result.duplicates).toEqual(["API_KEY", "API_KEY"]);
  });

  it("uses the backend 64 KiB value limit and rejects invalid data", () => {
    expect(bulkImportEnv(`OK=${"x".repeat(ENV_VALUE_LIMIT)}`, []).rejected).toEqual([]);
    expect(bulkImportEnv(`TOO_BIG=${"x".repeat(ENV_VALUE_LIMIT + 1)}`, []).rejected).toHaveLength(1);
    expect(bulkImportEnv("1BAD=x\nOK=x\x00y\nCARRIAGE=x\ry", []).rejected).toHaveLength(3);
  });

  it("merges previewed rows without mutating existing metadata", () => {
    const existing = [{ name: "PUBLIC", secret: false, value: "yes", has_value: true }];
    const merged = mergeImportedEnv(existing, [{ name: "TOKEN", value: "secret", secret: true }]);
    expect(merged[1]).toEqual({ name: "TOKEN", value: "secret", secret: true, has_value: false });
    expect(existing).toEqual([{ name: "PUBLIC", secret: false, value: "yes", has_value: true }]);
  });
});

describe("deployment state", () => {
  it("uses approval object identifiers", () => {
    const pf = { approvals: [{ id: "packages", label: "Install packages", detail: "apt" }], blockers: [], warnings: [] } as any;
    expect(approvalIds(pf)).toEqual(["packages"]);
    expect(needsApproval(pf)).toBe(true);
  });

  it("extracts blockers, warnings, and computes needsApproval correctly", () => {
    const pfWithBlockers = {
      approvals: [],
      blockers: [{ message: "Port 3000 in use" }],
      warnings: [{ message: "Node version deprecated" }],
    } as any;
    expect(preflightBlockers(pfWithBlockers)).toEqual(["Port 3000 in use"]);
    expect(preflightWarnings(pfWithBlockers)).toEqual(["Node version deprecated"]);
    expect(needsApproval(pfWithBlockers)).toBe(true);

    const cleanPf = { approvals: [], blockers: [], warnings: [] } as any;
    expect(needsApproval(cleanPf)).toBe(false);
  });

  it("describes mutations preferring mutation description over command", () => {
    expect(describeMutation({ mutation: "Install nginx", command: "apt-get install nginx" } as any)).toBe("Install nginx");
    expect(describeMutation({ mutation: "", command: "npm install" } as any)).toBe("npm install");
  });

  it("formats history timestamps", () => {
    const formatted = formatHistoryTime(1700000000000);
    expect(typeof formatted).toBe("string");
    expect(formatted.length).toBeGreaterThan(0);
  });

  it("maps channel cursors and filters out invalid or missing channels", () => {
    expect(cursorsFromSteps([{ channel: 3, cursor: 100 }, { channel: undefined, cursor: 50 }, { cursor: 10 } as any])).toEqual({ "3": 100 });
  });

  it("appends deploy output, trims to cap, and tracks gap presence", () => {
    // Null data returns original
    expect(appendDeployOutput("previous", undefined, 0, false)).toEqual({ text: "previous", gapNoted: false });
    expect(appendDeployOutput("previous", "", 0, true)).toEqual({ text: "previous", gapNoted: true });

    // Gap noted
    expect(appendDeployOutput("a", "b", 5, false)).toEqual({ text: "ab", gapNoted: true });

    // Cap slicing
    const bigString = "x".repeat(DEPLOY_OUTPUT_CAP + 50);
    const result = appendDeployOutput("", bigString, undefined, false);
    expect(result.text.length).toBe(DEPLOY_OUTPUT_CAP);
    expect(result.text).toBe("x".repeat(DEPLOY_OUTPUT_CAP));
  });
});
