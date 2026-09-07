// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { Mosaic, MosaicWindow, type MosaicNode } from "react-mosaic-component";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspaceDocking, WorkspaceDragHandle } from "./components/WorkspaceDocking";
import { WorkspacePaneSlot, WorkspaceSurfaces } from "./components/WorkspaceSurfaces";
import { dockWorkspacePane } from "./workspace-layout";

const initial: MosaicNode<string> = { type: "split", direction: "row", children: ["a", "b"], splitPercentages: [60, 40] };
function Harness({ enabled = true }: { enabled?: boolean }) {
  const [tree, setTree] = useState<MosaicNode<string> | null>(initial);
  const [status, setStatus] = useState("Ready");
  return <>
    <WorkspaceSurfaces paneKeys={["a", "b"]} renderPane={(id) => <input aria-label={`Draft ${id}`} defaultValue="unsaved text" />}>
      <WorkspaceDocking enabled={enabled} onStatus={setStatus} onDock={(source, target, position) => setTree((current) => dockWorkspacePane(current, source, target, position))}>
        <Mosaic className="oars-mosaic" value={tree} onChange={setTree} renderTabToolbarControls={() => null}
          renderTile={(id, path) => <MosaicWindow path={path} title={id} draggable={false}
            renderToolbar={() => <div data-workspace-pane={id}><WorkspaceDragHandle paneKey={id} onFocusPane={() => {}}>Drag {id}</WorkspaceDragHandle></div>}>
            <WorkspacePaneSlot paneKey={id} />
          </MosaicWindow>} />
      </WorkspaceDocking>
    </WorkspaceSurfaces>
    <output data-testid="tree">{JSON.stringify(tree)}</output><output>{status}</output>
  </>;
}

beforeEach(() => {
  vi.stubGlobal("PointerEvent", class extends MouseEvent {
    pointerId: number; isPrimary: boolean;
    constructor(type: string, init: PointerEventInit = {}) { super(type, init); this.pointerId = init.pointerId ?? 1; this.isPrimary = init.isPrimary ?? true; }
  });
  Object.defineProperties(HTMLElement.prototype, {
    setPointerCapture: { configurable: true, value: vi.fn() },
    releasePointerCapture: { configurable: true, value: vi.fn() },
    hasPointerCapture: { configurable: true, value: () => true },
  });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function setup(enabled = true) {
  const { container } = render(<Harness enabled={enabled} />);
  const source = screen.getByText("Drag a");
  const target = screen.getByText("Drag b").closest(".mosaic-window")!;
  vi.spyOn(target, "getBoundingClientRect").mockReturnValue({ left: 400, top: 0, width: 400, height: 400, right: 800, bottom: 400, x: 400, y: 0, toJSON() {} });
  Object.defineProperty(document, "elementFromPoint", { configurable: true, value: vi.fn(() => target) });
  const down = () => fireEvent.pointerDown(source, { pointerId: 1, button: 0, clientX: 100, clientY: 20 });
  const move = (x = 790, y = 200) => fireEvent.pointerMove(source, { pointerId: 1, clientX: x, clientY: y });
  const up = (x = 790, y = 200) => fireEvent.pointerUp(source, { pointerId: 1, clientX: x, clientY: y });
  return { source, target, down, move, up, container };
}
const tree = () => JSON.parse(screen.getByTestId("tree").textContent!);

describe("pointer docking in the native WebView", () => {
  it("commits with pointer events only, without hiding the source or restarting its editor", () => {
    const { down, move, up, container } = setup();
    const draft = screen.getByLabelText("Draft a");
    fireEvent.change(draft, { target: { value: "keep this edit" } });
    down(); move();
    expect(tree()).toEqual(initial);
    expect(container.querySelectorAll('[draggable="true"]')).toHaveLength(0);
    expect(screen.getByLabelText("Draft a")).toBe(draft);
    expect(document.querySelector(".workspace-dock-preview")?.textContent).toBe("Split right");
    up();
    expect(tree()).toMatchObject({ type: "split", children: ["b", "a"] });
    expect(screen.getByText("Pane moved.")).toBeTruthy();
    expect(screen.getByLabelText("Draft a")).toBe(draft);
    expect((draft as HTMLInputElement).value).toBe("keep this edit");
  });

  it("groups a center drop as tabs", () => {
    const { down, move, up } = setup(); down(); move(600); up(600);
    expect(tree()).toEqual({ type: "tabs", tabs: ["b", "a"], activeTabIndex: 1 });
  });

  it.each([
    { x: 410, y: 200, direction: "row", children: ["a", "b"] },
    { x: 600, y: 10, direction: "column", children: ["a", "b"] },
    { x: 600, y: 390, direction: "column", children: ["b", "a"] },
  ])("commits the edge at $x,$y", ({ x, y, direction, children }) => {
    const { down, move, up } = setup(); down(); move(x, y); up(x, y);
    expect(tree()).toMatchObject({ type: "split", direction, children });
  });

  it.each(["escape", "pointercancel", "blur", "outside", "capture lost"])("keeps the exact layout after %s", (reason) => {
    const { source, down, move, up } = setup(); down(); move();
    if (reason === "escape") fireEvent.keyDown(window, { key: "Escape" });
    if (reason === "pointercancel") fireEvent.pointerCancel(source, { pointerId: 1 });
    if (reason === "blur") fireEvent.blur(window);
    if (reason === "capture lost") fireEvent.lostPointerCapture(source, { pointerId: 1 });
    if (reason === "outside") vi.mocked(document.elementFromPoint).mockReturnValue(null);
    up();
    expect(tree()).toEqual(initial);
    expect(screen.getByText("Move cancelled. Layout unchanged.")).toBeTruthy();
    expect(document.querySelector(".workspace-dock-preview")).toBeNull();
  });

  it("does not move on a click or small pointer jitter", () => {
    const { down, move, up } = setup(); down(); move(103, 21); up(103, 21);
    expect(tree()).toEqual(initial);
    expect(screen.getByText("Ready")).toBeTruthy();
  });

  it("does not dock in focus or compact mode", () => {
    const { down, move, up } = setup(false); down(); move(); up();
    expect(tree()).toEqual(initial);
    expect(screen.getByText("Ready")).toBeTruthy();
  });
});
