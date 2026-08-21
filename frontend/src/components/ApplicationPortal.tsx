import { useEffect, useId, useState, type HTMLAttributes, type ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * Renders application-level UI outside pane, scroll, and stacking contexts.
 * Dialogs and viewport notifications must use this boundary when their
 * feature can be mounted inside a Mosaic window.
 */
export function ApplicationPortal({ children }: { children: ReactNode }) {
  if (typeof document === "undefined") return null;
  return createPortal(children, document.body);
}

const NOTICE_LAYER_ID = "oars-application-notices";
export const OVERLAY_STACK_EVENT = "oars:overlay-stack-change";

const overlayStack: string[] = [];
const overlaySubscribers = new Set<() => void>();

function announceOverlayStackChange() {
  for (const subscriber of overlaySubscribers) subscriber();
  if (typeof window !== "undefined") window.dispatchEvent(new Event(OVERLAY_STACK_EVENT));
}

function useApplicationOverlayStack() {
  const id = useId();
  const [, render] = useState(0);

  useEffect(() => {
    const update = () => render((version) => version + 1);
    overlaySubscribers.add(update);
    overlayStack.push(id);
    announceOverlayStackChange();

    return () => {
      overlaySubscribers.delete(update);
      const index = overlayStack.lastIndexOf(id);
      if (index >= 0) overlayStack.splice(index, 1);
      announceOverlayStackChange();
    };
  }, [id]);

  return overlayStack[overlayStack.length - 1] === id;
}

function noticeLayer(): HTMLElement | null {
  if (typeof document === "undefined") return null;
  let layer = document.getElementById(NOTICE_LAYER_ID);
  if (!layer) {
    layer = document.createElement("div");
    layer.id = NOTICE_LAYER_ID;
    layer.className = "oars-notice-layer";
    layer.setAttribute("aria-live", "polite");
    document.body.appendChild(layer);
  }
  return layer;
}

export function ApplicationNotice({ children }: { children: ReactNode }) {
  const layer = noticeLayer();
  return layer ? createPortal(children, layer) : null;
}

export function ApplicationOverlay({
  className = "oars-modal-overlay",
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  const isTopOverlay = useApplicationOverlayStack();

  return (
    <ApplicationPortal>
      <div
        className={className}
        {...props}
        aria-hidden={isTopOverlay ? undefined : true}
        data-overlay-state={isTopOverlay ? "top" : "covered"}
      >
        {children}
      </div>
    </ApplicationPortal>
  );
}
