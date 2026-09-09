import { useEffect, useMemo, useRef } from "react";
import { Mosaic, type MosaicNode, type MosaicPath } from "react-mosaic-component";
import { combineWorkspacePages, workspaceLayoutKeys, workspaceLayoutPages } from "../workspace-layout";
import { WorkspaceDockTab } from "./WorkspaceDockTab";
import type { ReactElement } from "react";

/** Scrolling changes visibility, never the lifetime of the session surfaces. */
export function WorkspacePages({ layout, activeKey, focused, navigationRevision = 0, onChange, onRelease, renderTile }: {
  layout: MosaicNode<string> | null;
  activeKey: string | null;
  focused: boolean;
  navigationRevision?: number;
  onChange: (layout: MosaicNode<string> | null) => void;
  onRelease: () => void;
  renderTile: (key: string, path: MosaicPath) => ReactElement;
}) {
  const root = useRef<HTMLDivElement>(null);
  const pages = useMemo(() => focused && activeKey ? [activeKey] : workspaceLayoutPages(layout), [layout, focused, activeKey]);
  const signature = pages.map(page => workspaceLayoutKeys(page).join("\0")).join("\n");
  useEffect(() => {
    if (!activeKey) return;
    if (focused) {
      if (root.current) root.current.scrollTop = 0;
      return;
    }
    const index = pages.findIndex(page => workspaceLayoutKeys(page).includes(activeKey));
    const page = root.current?.children[index] as HTMLElement | undefined;
    // Scroll only the workspace, not the document or a terminal's scrollback.
    if (page && root.current) root.current.scrollTop = page.offsetTop - root.current.offsetTop;
  }, [activeKey, focused, signature, navigationRevision]);

  return <div ref={root} className="workspace-pages" tabIndex={0} aria-label="Scrollable server workspace">
    {pages.map((page, index) => <section className="workspace-page" key={index} aria-label={`Workspace section ${index + 1} of ${pages.length}`}>
      <Mosaic<string> className="oars-mosaic" value={page}
        onChange={next => {
          if (focused || next === null) return;
          onChange(combineWorkspacePages(pages.map((item, itemIndex) => itemIndex === index ? next : item)));
        }}
        onRelease={() => { if (!focused) onRelease(); }}
        renderTabToolbarControls={() => null} canClose={() => "noClose"}
        renderTabButton={WorkspaceDockTab} renderTile={renderTile}
        resize={focused ? "DISABLED" : { minimumPaneSizePercentage: 18 }} zeroStateView={<div />} />
    </section>)}
  </div>;
}
