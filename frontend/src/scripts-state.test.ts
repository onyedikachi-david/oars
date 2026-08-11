// Pure state helpers for the Scripts workspace (spec 06) — see
// scripts-state.ts for the rules under test.

import { describe, expect, it } from "vitest";
import {
  appendOutput,
  detectVariables,
  filterScripts,
  prefillRunValues,
  rememberRunValues,
  formatLastRun,
  isDestructiveTagged,
  reconcileVariables,
  summarizeBroadcast,
  SCRIPT_COLORS,
  isValidColor,
  OUTPUT_CAP,
} from "./scripts-state";
import type { BroadcastServerResult, Script, ScriptVariable } from "./types";

const script = (over: Partial<Script>): Script => ({
  id: "s1",
  name: "tail errors",
  description: "tail the error log",
  tags: ["logs"],
  color: "",
  body: "tail -f /var/log/{{service}}/error.log",
  variables: [{ name: "service", label: "Service", secret_default: false }],
  created_at: 0,
  updated_at: 0,
  run_count: 0,
  last_run_at: null,
  ...over,
});

describe("detectVariables", () => {
  it("finds whole-word placeholders with the backend charset", () => {
    expect(detectVariables("echo {{a}} {{b_2}}")).toEqual(["a", "b_2"]);
  });

  it("dedupes and preserves first-use order", () => {
    expect(detectVariables("{{x}} {{y}} {{x}}")).toEqual(["x", "y"]);
  });

  it("ignores invalid names the backend would reject", () => {
    expect(detectVariables("{{bad-name}} {{1x}} {{x y}}")).toEqual([]);
  });

  it("ignores braces that are not placeholders", () => {
    expect(detectVariables("echo {a,b}")).toEqual([]);
  });
});

describe("reconcileVariables", () => {
  const saved: ScriptVariable[] = [
    { name: "service", label: "Service name", secret_default: true },
    { name: "gone", label: "Old", secret_default: false },
  ];

  it("preserves labels and secret defaults for matching names", () => {
    const out = reconcileVariables(["service", "newvar"], saved);
    expect(out[0]).toEqual({ name: "service", label: "Service name", secret_default: true });
    expect(out[1]).toEqual({ name: "newvar", label: "", secret_default: false });
  });

  it("keeps unused saved definitions visible", () => {
    const out = reconcileVariables(["newvar"], saved);
    // `service` and `gone` are both saved but not detected in the body:
    // both stay visible so an edit cannot silently drop a definition.
    expect(out.map((v) => v.name)).toEqual(["newvar", "service", "gone"]);
  });
});

describe("filterScripts", () => {
  const lib = [
    script({ id: "a", name: "tail errors", tags: ["logs"] }),
    script({ id: "b", name: "deploy", description: "ship the storefront", tags: ["deploy"] }),
  ];

  it("matches name, description, and tags case-insensitively", () => {
    expect(filterScripts(lib, "TAIL")).toHaveLength(1);
    expect(filterScripts(lib, "storefront")).toHaveLength(1);
    expect(filterScripts(lib, "deploy")).toHaveLength(1); // b: name + tag
    expect(filterScripts(lib, "logs")).toHaveLength(1); // a: tag only
  });

  it("empty query returns everything", () => {
    expect(filterScripts(lib, "  ")).toHaveLength(2);
  });

  it("combines free-text and exact tag filters", () => {
    expect(filterScripts(lib, "tail", "logs").map((item) => item.id)).toEqual(["a"]);
    expect(filterScripts(lib, "", "deploy").map((item) => item.id)).toEqual(["b"]);
    expect(filterScripts(lib, "tail", "deploy")).toEqual([]);
  });
});

describe("run value memory", () => {
  it("keeps non-secret values per script and never retains effective secrets", () => {
    const cache = rememberRunValues({}, script({ id: "a" }), {
      service: { value: "nginx", secret: false },
    });
    const promoted = rememberRunValues(cache, script({ id: "a" }), {
      service: { value: "production-password", secret: true },
    });
    const other = script({ id: "b" });

    expect(prefillRunValues(promoted, script({ id: "a" }))).toEqual({ values: {}, promoted: {} });
    expect(prefillRunValues(promoted, other)).toEqual({ values: {}, promoted: {} });
  });

  it("does not retain values whose stored definition is secret", () => {
    const secretScript = script({
      variables: [{ name: "service", label: "Service", secret_default: true }],
    });
    const cache = rememberRunValues({}, secretScript, {
      service: { value: "database-password", secret: false },
    });
    expect(prefillRunValues(cache, secretScript)).toEqual({ values: {}, promoted: {} });
  });
});

describe("formatLastRun", () => {
  it("says no runs yet without a run or stamp", () => {
    expect(formatLastRun(null, 0)).toBe("no runs yet");
    expect(formatLastRun(123, 0)).toBe("no runs yet");
  });

  it("renders relative units from millisecond stamps", () => {
    expect(formatLastRun(Date.now() - 30_000, 3)).toBe("just now");
    expect(formatLastRun(Date.now() - 5 * 60_000, 3)).toBe("5 min ago");
    expect(formatLastRun(Date.now() - 3 * 3600_000, 3)).toBe("3 h ago");
    expect(formatLastRun(Date.now() - 4 * 86400_000, 3)).toBe("4 d ago");
  });
});

describe("appendOutput", () => {
  it("appends deltas cumulatively", () => {
    const a = appendOutput("hello ", "world", 0, false);
    expect(a.text).toBe("hello world");
    expect(a.gapReported).toBe(false);
  });

  it("reports a gap once", () => {
    const a = appendOutput("", "chunk", 512, false);
    expect(a.gapReported).toBe(true);
    const b = appendOutput("chunk", "more", 0, a.gapReported);
    expect(b.gapReported).toBe(true);
  });

  it("caps retained output at the budget", () => {
    const big = "x".repeat(OUTPUT_CAP + 1000);
    const out = appendOutput("", big, 0, false);
    expect(out.text.length).toBe(OUTPUT_CAP);
  });
});

describe("summarizeBroadcast", () => {
  it("counts every status", () => {
    const servers: BroadcastServerResult[] = [
      { server_id: "a", status: "done", exit: 0, error: "" },
      { server_id: "b", status: "failed", exit: 2, error: "boom" },
      { server_id: "c", status: "running", exit: null, error: "" },
      { server_id: "d", status: "queued", exit: null, error: "" },
      { server_id: "e", status: "checking", exit: null, error: "" },
      { server_id: "f", status: "canceled", exit: null, error: "cancel requested" },
      { server_id: "g", status: "skipped", exit: null, error: "unreachable" },
    ];
    expect(summarizeBroadcast(servers)).toEqual({
      total: 7,
      queued: 1,
      checking: 1,
      running: 1,
      done: 1,
      failed: 1,
      canceled: 1,
      skipped: 1,
    });
  });
});

describe("colors and destructive tags", () => {
  it("accepts only the six swatches or empty", () => {
    expect(SCRIPT_COLORS).toHaveLength(6);
    for (const c of SCRIPT_COLORS) expect(isValidColor(c)).toBe(true);
    expect(isValidColor("")).toBe(true);
    expect(isValidColor("blue")).toBe(false);
    expect(isValidColor("#123456")).toBe(false);
  });

  it("destructive is an exact case-insensitive tag, never a color", () => {
    expect(isDestructiveTagged(["Destructive"])).toBe(true);
    expect(isDestructiveTagged(["logs", "DESTRUCTIVE"])).toBe(true);
    expect(isDestructiveTagged(["log-destructive"])).toBe(false);
    expect(isDestructiveTagged([])).toBe(false);
  });
});
