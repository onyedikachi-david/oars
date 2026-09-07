import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  MAX_WORKSPACE_PANES,
  buildWorkspaceLayout,
  workspaceLayoutKeys,
  retainWorkspacePanes,
  reconcileWorkspaceLayout,
  dockWorkspacePane,
  activateWorkspacePane,
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


});

describe("custom workspace state", () => {
  const tree = { type: "split" as const, direction: "row" as const, children: ["a", { type: "split" as const, direction: "column" as const, children: ["b", "c"], splitPercentages: [30, 70] }], splitPercentages: [60, 40] };

  it("preserves custom sizes and nested splits when opening another pane", () => {
    const next = reconcileWorkspaceLayout(tree, ["a", "b", "c", "d"], "balanced");
    expect(next).toMatchObject({ children: [tree, "d"] });
  });

  it("collapses only the affected split when a pane closes", () => {
    expect(retainWorkspacePanes(tree, ["a", "c"])).toEqual({ type: "split", direction: "row", children: ["a", "c"], splitPercentages: [60, 40] });
  });

  it("normalizes surviving weights after removing one of three siblings", () => {
    expect(retainWorkspacePanes({ type: "split", direction: "row", children: ["a", "b", "c"], splitPercentages: [20, 30, 50] }, ["a", "b"]))
      .toMatchObject({ splitPercentages: [40, 60] });
  });

  it.each(["left", "right", "top", "bottom", "tab"] as const)("moves a pane to %s without losing or duplicating other panes", (position) => {
    const next = dockWorkspacePane(tree, "c", "a", position);
    expect(workspaceLayoutKeys(next).sort()).toEqual(["a", "b", "c"]);
    expect(next).toMatchObject({ children: [position === "tab" ? { type: "tabs", tabs: ["a", "c"], activeTabIndex: 1 } : { type: "split", children: position === "left" || position === "top" ? ["c", "a"] : ["a", "c"] }, "b"] });
  });

  it("activates a grouped pane from the global server selector", () => {
    expect(activateWorkspacePane({ type: "tabs", tabs: ["a", "b"], activeTabIndex: 0 }, "b"))
      .toEqual({ type: "tabs", tabs: ["a", "b"], activeTabIndex: 1 });
  });

  it("retains tab selection when an earlier tab closes", () => {
    expect(retainWorkspacePanes({ type: "tabs", tabs: ["a", "b", "c"], activeTabIndex: 2 }, ["b", "c"]))
      .toEqual({ type: "tabs", tabs: ["b", "c"], activeTabIndex: 1 });
  });

  it("ignores a stale or self-targeted move", () => {
    expect(dockWorkspacePane(tree, "a", "a", "right")).toBe(tree);
    expect(dockWorkspacePane(tree, "missing", "a", "tab")).toBe(tree);
  });

  it.each(["tab-before", "tab-after"] as const)("reorders a grouped tab using %s", (position) => {
    const group = { type: "tabs" as const, tabs: ["a", "b", "c"], activeTabIndex: 2 };
    expect(dockWorkspacePane(group, "c", "a", position)).toEqual({
      type: "tabs", tabs: position === "tab-before" ? ["c", "a", "b"] : ["a", "c", "b"], activeTabIndex: position === "tab-before" ? 0 : 1,
    });
  });

  it("splits the selected tab out of its own group", () => {
    expect(dockWorkspacePane({ type: "tabs", tabs: ["a", "b"], activeTabIndex: 1 }, "b", "a", "right"))
      .toMatchObject({ type: "split", direction: "row", children: ["a", "b"] });
  });
});
