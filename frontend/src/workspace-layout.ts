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

/** Keep custom splits and tab selection when a pane closes. */
export function retainWorkspacePanes(node: MosaicNode<string> | null, keys: readonly string[]): MosaicNode<string> | null {
  if (node === null) return null;
  if (typeof node === "string") return keys.includes(node) ? node : null;
  if (node.type === "tabs") {
    const tabs = node.tabs.filter((key) => keys.includes(key));
    if (tabs.length < 2) return tabs[0] ?? null;
    return { ...node, tabs, activeTabIndex: Math.max(0, tabs.indexOf(node.tabs[node.activeTabIndex])) };
  }
  const retained = node.children.map((child, index) => ({ child: retainWorkspacePanes(child, keys), size: node.splitPercentages?.[index] ?? 100 / node.children.length }))
    .filter((entry): entry is { child: MosaicNode<string>; size: number } => entry.child !== null);
  if (retained.length < 2) return retained[0]?.child ?? null;
  const total = retained.reduce((sum, entry) => sum + entry.size, 0);
  return { ...node, children: retained.map((entry) => entry.child), splitPercentages: retained.map((entry) => total > 0 ? entry.size / total * 100 : 100 / retained.length) };
}

export function reconcileWorkspaceLayout(node: MosaicNode<string> | null, keys: string[], variant: WorkspaceLayoutVariant): MosaicNode<string> | null {
  const retained = retainWorkspacePanes(node, keys);
  if (retained === null) return buildWorkspaceLayout(keys, variant);
  const existing = workspaceLayoutKeys(retained);
  return keys.filter((key) => !existing.includes(key)).reduce<MosaicNode<string>>(
    (current, key) => split("row", [current, key], typeof current === "string" ? [50, 50] : [65, 35]), retained,
  );
}

export type WorkspaceDockPosition = "left" | "right" | "top" | "bottom" | "tab" | "tab-before" | "tab-after";

export function dockWorkspacePane(node: MosaicNode<string> | null, source: string, target: string, position: WorkspaceDockPosition): MosaicNode<string> | null {
  const keys = workspaceLayoutKeys(node);
  if (source === target || !keys.includes(source) || !keys.includes(target)) return node;
  const remaining = retainWorkspacePanes(node, keys.filter((key) => key !== source));
  const insert = (current: MosaicNode<string>): MosaicNode<string> => {
    if (typeof current !== "string" && current.type === "split") return { ...current, children: current.children.map(insert) };
    if (!(typeof current === "string" ? current === target : current.tabs.includes(target))) return current;
    if (position === "tab" || position === "tab-before" || position === "tab-after") {
      const tabs = typeof current === "string" ? [current] : [...current.tabs];
      const index = position === "tab" ? tabs.length : tabs.indexOf(target) + (position === "tab-after" ? 1 : 0);
      tabs.splice(index, 0, source);
      return { type: "tabs", tabs, activeTabIndex: index };
    }
    return split(position === "left" || position === "right" ? "row" : "column",
      position === "left" || position === "top" ? [source, current] : [current, source]);
  };
  return remaining === null ? node : insert(remaining);
}

export function activateWorkspacePane(node: MosaicNode<string> | null, key: string): MosaicNode<string> | null {
  if (node === null || typeof node === "string") return node;
  if (node.type === "tabs") {
    const index = node.tabs.indexOf(key);
    return index < 0 || index === node.activeTabIndex ? node : { ...node, activeTabIndex: index };
  }
  const children = node.children.map((child) => activateWorkspacePane(child, key)!);
  return children.every((child, index) => child === node.children[index]) ? node : { ...node, children };
}
