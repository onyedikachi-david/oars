// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import React, { useRef } from "react";
import { useRovingListNav } from "./components/useRovingListNav";

function TestList({
  items,
  orientation = "vertical",
  wrap = true,
  onSelect,
}: {
  items: { id: string; name: string }[];
  orientation?: "vertical" | "horizontal" | "both";
  wrap?: boolean;
  onSelect?: (id: string, item: any) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { focusedIndex, setFocusedIndex, getItemProps } = useRovingListNav({
    itemCount: items.length,
    orientation,
    wrap,
    containerRef,
    onSelect: (index) => onSelect?.(items[index].id, items[index]),
  });

  return (
    <div ref={containerRef} role="listbox" aria-label="Test List">
      {items.map((item, index) => {
        const props = getItemProps(index);
        return (
          <button key={item.id} {...props} data-testid={`item-${item.id}`}>
            {item.name}
          </button>
        );
      })}
    </div>
  );
}

describe("useRovingListNav", () => {
  afterEach(() => {
    cleanup();
  });

  const testItems = [
    { id: "1", name: "Apple" },
    { id: "2", name: "Banana" },
    { id: "3", name: "Cherry" },
  ];

  it("sets tabIndex=0 on initial item and tabIndex=-1 on others", () => {
    render(<TestList items={testItems} />);

    const item1 = screen.getByTestId("item-1");
    const item2 = screen.getByTestId("item-2");
    const item3 = screen.getByTestId("item-3");

    expect(item1.getAttribute("tabindex")).toBe("0");
    expect(item2.getAttribute("tabindex")).toBe("-1");
    expect(item3.getAttribute("tabindex")).toBe("-1");
  });

  it("moves focus on ArrowDown and ArrowUp", () => {
    render(<TestList items={testItems} />);

    const item1 = screen.getByTestId("item-1");
    const item2 = screen.getByTestId("item-2");
    const item3 = screen.getByTestId("item-3");

    item1.focus();
    fireEvent.keyDown(item1, { key: "ArrowDown" });

    expect(item2.getAttribute("tabindex")).toBe("0");
    expect(item1.getAttribute("tabindex")).toBe("-1");

    fireEvent.keyDown(item2, { key: "ArrowDown" });
    expect(item3.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(item3, { key: "ArrowUp" });
    expect(item2.getAttribute("tabindex")).toBe("0");
  });

  it("wraps navigation around when wrap=true", () => {
    render(<TestList items={testItems} wrap={true} />);

    const item1 = screen.getByTestId("item-1");
    const item3 = screen.getByTestId("item-3");

    item1.focus();
    fireEvent.keyDown(item1, { key: "ArrowUp" });
    expect(item3.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(item3, { key: "ArrowDown" });
    expect(item1.getAttribute("tabindex")).toBe("0");
  });

  it("handles Home and End keys", () => {
    render(<TestList items={testItems} />);

    const item1 = screen.getByTestId("item-1");
    const item2 = screen.getByTestId("item-2");
    const item3 = screen.getByTestId("item-3");

    item1.focus();
    fireEvent.keyDown(item1, { key: "End" });
    expect(item3.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(item3, { key: "Home" });
    expect(item1.getAttribute("tabindex")).toBe("0");
  });

  it("calls onSelect on Enter and Space", () => {
    const onSelect = vi.fn();
    render(<TestList items={testItems} onSelect={onSelect} />);

    const item1 = screen.getByTestId("item-1");
    item1.focus();

    fireEvent.keyDown(item1, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith("1", testItems[0]);

    fireEvent.keyDown(item1, { key: " " });
    expect(onSelect).toHaveBeenCalledWith("1", testItems[0]);
  });
});
