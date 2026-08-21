import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  MAX_WORKSPACE_PANES,
  buildWorkspaceLayout,
  workspaceLayoutKeys,
} from "./workspace-layout";

describe("workspace layouts", () => {
  it("keeps all panes in every preset", () => {
    const keys = ["alpha", "beta", "gamma", "delta"];
    for (const variant of ["balanced", "columns", "focus"] as const) {
      expect(workspaceLayoutKeys(buildWorkspaceLayout(keys, variant))).toEqual(keys);
    }
  });

  it("uses a two-by-two split for four balanced panes", () => {
    const layout = buildWorkspaceLayout(["a", "b", "c", "d"], "balanced");
    expect(layout).toMatchObject({
      type: "split",
      direction: "column",
      children: [
        { type: "split", direction: "row", children: ["a", "b"] },
        { type: "split", direction: "row", children: ["c", "d"] },
      ],
    });
  });

  it("never creates more than the supported pane limit", () => {
    const keys = Array.from({ length: MAX_WORKSPACE_PANES + 2 }, (_, index) => String(index));
    expect(workspaceLayoutKeys(buildWorkspaceLayout(keys, "columns"))).toHaveLength(MAX_WORKSPACE_PANES);
  });

  it("stacks two panes at narrow widths", () => {
    expect(buildWorkspaceLayout(["a", "b"], "focus", true)).toMatchObject({
      type: "split",
      direction: "column",
      children: ["a", "b"],
    });
  });

  it("uses a two-by-two layout for four compact panes", () => {
    expect(buildWorkspaceLayout(["a", "b", "c", "d"], "focus", true)).toMatchObject({
      type: "split",
      direction: "column",
      children: [
        { type: "split", direction: "row", children: ["a", "b"] },
        { type: "split", direction: "row", children: ["c", "d"] },
      ],
    });
  });

  it("adapts feature layouts to Mosaic pane width", () => {
    const css = readFileSync(`${process.cwd()}/src/index.css`, "utf8");
    const start = css.indexOf("@container workspace-pane (max-width: 760px)");
    const end = css.indexOf("@container workspace-pane (max-width: 560px)", start);
    const compactPaneRules = css.slice(start, end);

    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(compactPaneRules).toContain(".monitor-process-table");
    expect(compactPaneRules).toContain(".logs-workspace");
    expect(compactPaneRules).toContain(".fs-panes");
    expect(compactPaneRules).toContain(".scripts-layout");
  });

  it("uses Mosaic's controlled-state and native preview contracts directly", () => {
    const app = readFileSync(`${process.cwd()}/src/App.tsx`, "utf8");
    const css = readFileSync(`${process.cwd()}/src/index.css`, "utf8");

    expect(app).not.toContain("renderPreview=");
    expect(app).toContain("onChange={setMosaicLayout}");
    expect(css).toContain(".oars-mosaic .mosaic-preview");
    expect(css).toContain(".drop-target.drop-target-hover");
  });
});
