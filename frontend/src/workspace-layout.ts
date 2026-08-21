import type { MosaicNode } from "react-mosaic-component";

export const MAX_WORKSPACE_PANES = 4;

export type WorkspaceLayoutVariant = "balanced" | "columns" | "focus";

export const WORKSPACE_LAYOUT_VARIANTS: ReadonlyArray<{
  id: WorkspaceLayoutVariant;
  label: string;
  description: string;
}> = [
  {
    id: "balanced",
    label: "Balanced",
    description: "Even space for side-by-side work.",
  },
  {
    id: "columns",
    label: "Columns",
    description: "Keep every server at the same height.",
  },
  {
    id: "focus",
    label: "Focus",
    description: "Give the first server more room.",
  },
];

function split(
  direction: "row" | "column",
  children: MosaicNode<string>[],
  splitPercentages?: number[],
): MosaicNode<string> {
  return { type: "split", direction, children, splitPercentages };
}

export function buildWorkspaceLayout(
  keys: string[],
  variant: WorkspaceLayoutVariant,
  compact = false,
): MosaicNode<string> | null {
  const panes = keys.slice(0, MAX_WORKSPACE_PANES);
  if (panes.length === 0) return null;
  if (panes.length === 1) return panes[0];

  if (variant === "columns" && !compact) {
    return split("row", panes);
  }

  if (variant === "focus" && !compact) {
    return split(
      "row",
      [panes[0], panes.length === 2 ? panes[1] : split("column", panes.slice(1))],
      [64, 36],
    );
  }

  if (panes.length === 2) return split(compact ? "column" : "row", panes);
  if (panes.length === 3) {
    return split("row", [panes[0], split("column", panes.slice(1))], [56, 44]);
  }

  return split(
    "column",
    [split("row", panes.slice(0, 2)), split("row", panes.slice(2, 4))],
  );
}

export function workspaceLayoutKeys(node: MosaicNode<string> | null): string[] {
  if (node === null) return [];
  if (typeof node === "string") return [node];
  if (node.type === "tabs") return node.tabs;
  return node.children.flatMap(workspaceLayoutKeys);
}
