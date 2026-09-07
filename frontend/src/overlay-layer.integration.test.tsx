import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { DeployEditorModal } from "./features/deploy/components/DeployEditorModal";
import { emptyEditor } from "./features/deploy/utils";
import { ApplicationNotice, ApplicationOverlay } from "./components/ApplicationPortal";

describe("application overlay layer", () => {
  it("renders the Deploy editor outside its Mosaic pane", () => {
    const editor = emptyEditor("server-1");

    render(
      <div className="mosaic-window" data-testid="pane-boundary">
        <DeployEditorModal
          editor={editor}
          setEditor={vi.fn()}
          busy={false}
          error={null}
          bulkText=""
          setBulkText={vi.fn()}
          bulkPreview={null}
          onPreview={vi.fn()}
          onApplyPreview={vi.fn()}
          onCancel={vi.fn()}
          onSave={vi.fn()}
        />
      </div>,
    );

    const dialog = screen.getByRole("dialog", { name: "New application" });
    expect(dialog.closest(".mosaic-window")).toBeNull();
    expect(dialog.parentElement?.parentElement).toBe(document.body);
  });

  it("renders viewport notices outside their Mosaic pane", () => {
    render(
      <div className="mosaic-window">
        <ApplicationNotice>
          <div role="status">Saved</div>
        </ApplicationNotice>
      </div>,
    );

    const notice = screen.getByRole("status");
    expect(notice.closest(".mosaic-window")).toBeNull();
    expect(notice.parentElement?.id).toBe("oars-application-notices");
  });

  it("exposes only the top application dialog when panes open overlays together", () => {
    const { rerender } = render(
      <>
        <ApplicationOverlay key="first">
          <div role="dialog" aria-modal="true" aria-label="First dialog">First</div>
        </ApplicationOverlay>
        <ApplicationOverlay key="second">
          <div role="dialog" aria-modal="true" aria-label="Second dialog">Second</div>
        </ApplicationOverlay>
      </>,
    );

    expect(screen.getByText("First").parentElement?.getAttribute("aria-hidden")).toBe("true");
    expect(screen.getByRole("dialog", { name: "Second dialog" })).toBeTruthy();

    rerender(
      <ApplicationOverlay key="first">
        <div role="dialog" aria-modal="true" aria-label="First dialog">First</div>
      </ApplicationOverlay>,
    );

    expect(screen.getByRole("dialog", { name: "First dialog" })).toBeTruthy();
    expect(screen.getByText("First").parentElement?.hasAttribute("aria-hidden")).toBe(false);
  });

  it("keeps raw modal overlays inside the application portal component", () => {
    const sourceRoot = `${process.cwd()}/src`;
    const files: string[] = [];
    const visit = (directory: string) => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = `${directory}/${entry.name}`;
        if (entry.isDirectory()) visit(path);
        else if (entry.name.endsWith(".tsx") && !entry.name.endsWith(".test.tsx")) files.push(path);
      }
    };
    visit(sourceRoot);

    const violations = files
      .filter((path) => !path.endsWith("/components/ApplicationPortal.tsx"))
      .filter((path) => readFileSync(path, "utf8").includes("oars-modal-overlay"));

    expect(violations).toEqual([]);
  });
});
