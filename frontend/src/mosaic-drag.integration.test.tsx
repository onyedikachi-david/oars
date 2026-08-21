// @vitest-environment jsdom

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { useState } from "react";
import { Mosaic, MosaicWindow, type MosaicNode } from "react-mosaic-component";
import { describe, expect, it } from "vitest";

const initialTree: MosaicNode<string> = {
  type: "split",
  direction: "row",
  children: ["a", "b"],
};

function DragHarness() {
  const [tree, setTree] = useState<MosaicNode<string> | null>(initialTree);

  return (
    <div style={{ width: 900, height: 600 }}>
      <Mosaic<string>
        className="oars-mosaic"
        value={tree}
        onChange={setTree}
        renderTile={(id, path) => (
          <MosaicWindow<string>
            path={path}
            title={id}
            renderToolbar={() => <div data-testid={`drag-${id}`}>Drag {id}</div>}
          >
            <div>Pane {id}</div>
          </MosaicWindow>
        )}
      />
    </div>
  );
}

function dataTransfer() {
  return {
    dropEffect: "move",
    effectAllowed: "all",
    files: [],
    items: [],
    types: [],
    setData() {},
    getData() { return ""; },
    clearData() {},
    setDragImage() {},
  };
}

describe("Mosaic desktop drag lifecycle", () => {
  it("enters Mosaic dragging state with the library preview", async () => {
    const { container } = render(<DragHarness />);

    fireEvent.dragStart(screen.getByTestId("drag-a"), { dataTransfer: dataTransfer() });

    await waitFor(() => expect(container.querySelector(".mosaic.-dragging")).not.toBeNull());
    expect(container.querySelector(".mosaic-preview")).not.toBeNull();
  });

  it("commits a pane reorder through the controlled onChange tree", async () => {
    const { container } = render(<DragHarness />);
    const source = screen.getByTestId("drag-a");
    const transfer = dataTransfer();

    fireEvent.dragStart(source, { dataTransfer: transfer });
    await waitFor(() => expect(container.querySelector(".mosaic.-dragging")).not.toBeNull());

    const windows = container.querySelectorAll(".mosaic-window");
    const target = windows[1].querySelector<HTMLElement>(".drop-target.right");
    expect(target).not.toBeNull();
    fireEvent.dragEnter(target!, { dataTransfer: transfer });
    fireEvent.dragOver(target!, { dataTransfer: transfer });

    await waitFor(() => expect(windows[1].classList.contains("drop-target-hover")).toBe(true));
    const css = readFileSync(`${process.cwd()}/src/index.css`, "utf8");
    expect(css).toContain(".oars-mosaic.-dragging .mosaic-window.drop-target-hover");

    fireEvent.drop(target!, { dataTransfer: transfer });
    fireEvent.dragEnd(source, { dataTransfer: transfer });

    await waitFor(() => {
      const panes = Array.from(container.querySelectorAll(".mosaic-window > .mosaic-window-body"))
        .map((node) => node.textContent?.trim())
        .filter(Boolean);
      expect(panes).toEqual(["Pane b", "Pane a"]);
    });
  });
});
