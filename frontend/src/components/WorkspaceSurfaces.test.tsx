// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useEffect, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Mosaic, MosaicWindow, type MosaicNode } from "react-mosaic-component";
import { WorkspacePaneSlot, WorkspaceSurfaces } from "./WorkspaceSurfaces";
import { WorkspaceDockTab, WorkspaceDockTabContext } from "./WorkspaceDockTab";

afterEach(cleanup);

describe("workspace content lifetime", () => {
  it("keeps a grouped tab focused across parent updates and activates it before dragging", () => {
    const select = vi.fn();
    function Harness({ label }: { label: string }) {
      return <WorkspaceDockTabContext.Provider value={{ names: { a: label, b: "Second pane" }, onSelect: select }}>
        <Mosaic value={{ type: "tabs", tabs: ["a", "b"], activeTabIndex: 0 }} onChange={() => {}}
          renderTabButton={WorkspaceDockTab} renderTabToolbarControls={() => null}
          renderTile={(id, path) => <MosaicWindow path={path} title={id}>Content {id}</MosaicWindow>} />
      </WorkspaceDockTabContext.Provider>;
    }
    const { rerender } = render(<Harness label="First pane" />);
    const button = screen.getByRole("button", { name: "First pane" });
    button.focus();
    rerender(<Harness label="Renamed pane" />);
    expect(screen.getByRole("button", { name: "Renamed pane" })).toBe(button);
    expect(document.activeElement).toBe(button);
    fireEvent.pointerDown(screen.getByRole("button", { name: "Second pane" }));
    expect(select).toHaveBeenCalledWith("b");
  });

  it("keeps local edits and mounted sessions through reorder, grouping and focus, then cleans up on close", () => {
    const mount = vi.fn();
    const unmount = vi.fn();
    function Editor({ id }: { id: string }) {
      const [value, setValue] = useState("");
      useEffect(() => { mount(id); return () => { unmount(id); }; }, [id]);
      return <input aria-label={`Draft ${id}`} value={value} onChange={(event) => setValue(event.target.value)} />;
    }
    function Harness({ tree, keys = ["a", "b"] }: { tree: MosaicNode<string>; keys?: string[] }) {
      return <WorkspaceSurfaces paneKeys={keys} renderPane={(id) => <Editor id={id} />}>
        <Mosaic value={tree} onChange={() => {}} renderTile={(id, path) => <MosaicWindow path={path} title={id}><WorkspacePaneSlot paneKey={id} /></MosaicWindow>} />
      </WorkspaceSurfaces>;
    }
    const { rerender } = render(<Harness tree={{ type: "split", direction: "row", children: ["a", "b"] }} />);
    const draft = screen.getByLabelText("Draft a");
    fireEvent.change(draft, { target: { value: "unfinished command" } });
    rerender(<Harness tree={{ type: "split", direction: "column", children: ["b", "a"] }} />);
    expect(screen.getByLabelText("Draft a")).toBe(draft);
    rerender(<Harness tree={{ type: "tabs", tabs: ["a", "b"], activeTabIndex: 1 }} />);
    expect(screen.queryByLabelText("Draft a")).toBeNull();
    rerender(<Harness tree="a" />);
    expect(screen.getByLabelText("Draft a")).toBe(draft);
    expect((draft as HTMLInputElement).value).toBe("unfinished command");
    expect(mount.mock.calls).toEqual([["a"], ["b"]]);
    expect(unmount).not.toHaveBeenCalled();
    rerender(<Harness tree="b" keys={["b"]} />);
    expect(unmount.mock.calls).toEqual([["a"]]);
  });
});
