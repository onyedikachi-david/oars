import { useCallback, useEffect, useRef, useState } from "react";

export interface UseRovingListNavOptions {
  itemCount: number;
  initialIndex?: number;
  wrap?: boolean;
  orientation?: "vertical" | "horizontal" | "both";
  onSelect?: (index: number) => void;
  containerRef?: React.RefObject<HTMLDivElement | null>;
}

export function useRovingListNav({
  itemCount,
  initialIndex = 0,
  wrap = true,
  orientation = "vertical",
  onSelect,
  containerRef: externalContainerRef,
}: UseRovingListNavOptions) {
  const [focusedIndex, setFocusedIndex] = useState(() => {
    if (itemCount === 0) return -1;
    return Math.max(0, Math.min(initialIndex, itemCount - 1));
  });

  const internalContainerRef = useRef<HTMLDivElement>(null);
  const containerRef = externalContainerRef || internalContainerRef;
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  // Clamp focusedIndex when itemCount changes
  useEffect(() => {
    if (itemCount === 0) {
      setFocusedIndex(-1);
    } else {
      setFocusedIndex((prev) => {
        if (prev < 0) return 0;
        if (prev >= itemCount) return itemCount - 1;
        return prev;
      });
    }
  }, [itemCount]);

  const moveFocus = useCallback(
    (nextIndex: number) => {
      if (itemCount === 0) return;
      let target = nextIndex;
      if (wrap) {
        target = ((target % itemCount) + itemCount) % itemCount;
      } else {
        target = Math.max(0, Math.min(target, itemCount - 1));
      }
      setFocusedIndex(target);

      // Auto-scroll into view and focus element
      if (containerRef.current) {
        const items = containerRef.current.querySelectorAll<HTMLElement>(
          '[role="option"], [data-roving-item="true"]',
        );
        const el = items[target];
        if (el) {
          if (typeof el.scrollIntoView === "function") {
            el.scrollIntoView({ block: "nearest", inline: "nearest" });
          }
          if (typeof el.focus === "function") {
            el.focus();
          }
        }
      }
    },
    [containerRef, itemCount, wrap],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent, indexOverride?: number) => {
      if (itemCount === 0) return;
      const current = indexOverride ?? (focusedIndex >= 0 ? focusedIndex : 0);

      const isVertical = orientation === "vertical" || orientation === "both";
      const isHorizontal = orientation === "horizontal" || orientation === "both";

      if ((isVertical && e.key === "ArrowDown") || (isHorizontal && e.key === "ArrowRight")) {
        e.preventDefault();
        moveFocus(current + 1);
      } else if ((isVertical && e.key === "ArrowUp") || (isHorizontal && e.key === "ArrowLeft")) {
        e.preventDefault();
        moveFocus(current - 1);
      } else if (e.key === "Home" || e.key === "PageUp") {
        e.preventDefault();
        moveFocus(0);
      } else if (e.key === "End" || e.key === "PageDown") {
        e.preventDefault();
        moveFocus(itemCount - 1);
      } else if (e.key === "Enter" || e.key === " ") {
        if (current >= 0 && current < itemCount) {
          e.preventDefault();
          onSelectRef.current?.(current);
        }
      }
    },
    [focusedIndex, itemCount, moveFocus, orientation],
  );

  const getItemProps = useCallback(
    (index: number, isSelected = false) => ({
      role: "option" as const,
      tabIndex: index === focusedIndex ? 0 : -1,
      "aria-selected": isSelected,
      "data-roving-item": "true",
      onFocus: () => setFocusedIndex(index),
      onKeyDown: (e: React.KeyboardEvent) => handleKeyDown(e, index),
    }),
    [focusedIndex, handleKeyDown],
  );

  return {
    focusedIndex,
    setFocusedIndex,
    containerRef,
    moveFocus,
    handleKeyDown,
    getItemProps,
  };
}
