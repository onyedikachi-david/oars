import { useEffect, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MosaicWindow } from "react-mosaic-component";
import { WorkspacePages } from "./WorkspacePages";
import { WorkspaceSurfaces, WorkspacePaneSlot } from "./WorkspaceSurfaces";
import { buildWorkspaceLayout } from "../workspace-layout";

it("keeps all fifteen sessions mounted while scrolling, focusing and switching layouts", () => {
  const started = vi.fn(); const stopped = vi.fn();
  const keys = Array.from({length: 15}, (_, i) => `server-${i}`);
  function Session({id}: {id:string}) {
    const [draft, setDraft] = useState("");
    useEffect(() => { started(id); return () => stopped(id); }, [id]);
    return <input aria-label={`Draft ${id}`} value={draft} onChange={e=>setDraft(e.target.value)} />;
  }
  function Harness({focused=false, active="server-0", columns=false, navigationRevision=0}: {focused?:boolean; active?:string; columns?:boolean; navigationRevision?:number}) {
    return <WorkspaceSurfaces paneKeys={keys} renderPane={id=><Session id={id} />}>
      <WorkspacePages layout={buildWorkspaceLayout(keys,columns?"columns":"balanced")} activeKey={active} focused={focused} navigationRevision={navigationRevision} onChange={()=>{}} onRelease={()=>{}}
        renderTile={(id,path)=><MosaicWindow path={path} title={id}><WorkspacePaneSlot paneKey={id} /></MosaicWindow>} />
    </WorkspaceSurfaces>;
  }
  const {rerender,container,unmount}=render(<Harness />);
  expect(container.querySelectorAll('.workspace-page')).toHaveLength(4);
  expect(container.querySelectorAll('.mosaic-window')).toHaveLength(15);
  const draft=screen.getByLabelText('Draft server-14');
  fireEvent.change(draft,{target:{value:'unfinished command'}});
  const scroll=screen.getByLabelText('Scrollable server workspace');
  Object.defineProperty(container.querySelectorAll('.workspace-page')[3],'offsetTop',{configurable:true,value:1800});
  rerender(<Harness active="server-14" />);
  expect(scroll.scrollTop).toBe(1800);
  scroll.scrollTop=0;
  rerender(<Harness active="server-14" navigationRevision={1} />);
  expect(scroll.scrollTop).toBe(1800);
  rerender(<Harness active="server-14" focused />);
  expect(scroll.scrollTop).toBe(0);
  expect(container.querySelectorAll('.workspace-page')).toHaveLength(1);
  expect(screen.getByLabelText('Draft server-14')).toBe(draft);
  rerender(<Harness active="server-14" columns />);
  expect(screen.getByLabelText('Draft server-14')).toBe(draft);
  expect((draft as HTMLInputElement).value).toBe('unfinished command');
  expect(started).toHaveBeenCalledTimes(15);
  expect(stopped).not.toHaveBeenCalled();
  unmount(); expect(stopped).toHaveBeenCalledTimes(15);
});
