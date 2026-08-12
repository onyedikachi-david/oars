import { describe, expect, it } from "vitest";
import { ENV_VALUE_LIMIT, appendDeployOutput, approvalIds, bulkImportEnv, cursorsFromSteps, mergeImportedEnv, needsApproval } from "./deploy-state";

describe("bulkImportEnv", () => {
  it("preserves every byte after the first equals and defaults to secret", () => {
    const result = bulkImportEnv(' export TOKEN=  "a=b"  \nEMPTY=\n', []);
    expect(result.rows).toEqual([
      { name: "TOKEN", value: '  "a=b"  ', secret: true },
      { name: "EMPTY", value: "", secret: true },
    ]);
    expect(result.preview).toBe("TOKEN=••••••••\nEMPTY=••••••••");
  });

  it("rejects duplicate names instead of replacing an existing value", () => {
    const result = bulkImportEnv("API_KEY=new\nAPI_KEY=again", [{ name: "API_KEY", secret: true, value: "", has_value: true }]);
    expect(result.rows).toEqual([]);
    expect(result.duplicates).toEqual(["API_KEY", "API_KEY"]);
  });

  it("uses the backend 64 KiB value limit and rejects invalid data", () => {
    expect(bulkImportEnv(`OK=${"x".repeat(ENV_VALUE_LIMIT)}`, []).rejected).toEqual([]);
    expect(bulkImportEnv(`TOO_BIG=${"x".repeat(ENV_VALUE_LIMIT + 1)}`, []).rejected).toHaveLength(1);
    expect(bulkImportEnv("1BAD=x\nOK=x\x00y", []).rejected).toHaveLength(2);
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

  it("maps channel cursors and reports output gaps", () => {
    expect(cursorsFromSteps([{ channel: 3, cursor: 100 }])).toEqual({ "3": 100 });
    expect(appendDeployOutput("a", "b", 5, false)).toEqual({ text: "ab", gapNoted: true });
  });
});
