// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WorkspaceLayoutPicker } from "./WorkspaceLayoutPicker";

describe("WorkspaceLayoutPicker", () => {
  afterEach(cleanup);

  it("renders its menu outside the clipped tab bar", () => {
    render(
      <div data-testid="clipped-tabbar" style={{ overflow: "hidden" }}>
        <WorkspaceLayoutPicker
          value="balanced"
          defaultValue="balanced"
          onChange={vi.fn()}
          onSaveDefault={vi.fn()}
        />
      </div>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Choose workspace layout" }));

    const menu = screen.getByRole("menu", { name: "Workspace layout" });
    expect(menu.closest('[data-testid="clipped-tabbar"]')).toBeNull();
    expect(menu.parentElement).toBe(document.body);
  });

  it("supports menu keyboard movement and restores focus on Escape", () => {
    render(
      <WorkspaceLayoutPicker
        value="balanced"
        defaultValue="balanced"
        onChange={vi.fn()}
        onSaveDefault={vi.fn()}
      />,
    );

    const trigger = screen.getByRole("button", { name: "Choose workspace layout" });
    fireEvent.click(trigger);
    const balanced = screen.getByRole("menuitemradio", { name: /Balanced/ });
    balanced.focus();
    fireEvent.keyDown(balanced, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByRole("menuitemradio", { name: /Columns/ }));

    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    expect(screen.queryByRole("menu", { name: "Workspace layout" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
