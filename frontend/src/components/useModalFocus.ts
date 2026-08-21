import { useEffect, useRef } from "react";
import { OVERLAY_STACK_EVENT } from "./ApplicationPortal";

export const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]), [contenteditable]:not([contenteditable="false"])';

function isVisible(el: HTMLElement): boolean {
  if (el.closest('[aria-hidden="true"]')) return false;
  if (el.getAttribute("aria-hidden") === "true") return false;
  if (el.hasAttribute("disabled")) return false;
  if (typeof window !== "undefined" && window.getComputedStyle) {
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
  }
  return true;
}

function modalDialogs(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"][aria-modal="true"]'))
    .filter((dialog) => document.body.contains(dialog) && isVisible(dialog));
}

function isTopmostDialog(dialog: HTMLElement | null): boolean {
  if (!dialog) return false;
  const dialogs = modalDialogs();
  return dialogs[dialogs.length - 1] === dialog;
}

function focusFirst(dialog: HTMLElement, initialSelector?: string) {
  const selector = initialSelector ?? FOCUSABLE_SELECTOR;
  const target = dialog.querySelector<HTMLElement>(selector);
  if (target && isVisible(target)) {
    target.focus();
    return;
  }
  const allFocusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(isVisible);
  if (allFocusable.length > 0) {
    allFocusable[0].focus();
    return;
  }
  if (!dialog.hasAttribute("tabindex")) dialog.setAttribute("tabindex", "-1");
  dialog.focus();
}

/** Shared Oars dialog behavior: one initial focus, Escape, focus trap, and
 * focus restoration. Callback changes never reset focus while a user types. */
export function useModalFocus(onCancel: () => void, initialSelector?: string, canClose = true) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef(onCancel);
  const canCloseRef = useRef(canClose);
  cancelRef.current = onCancel;
  canCloseRef.current = canClose;

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;

    const frameId = requestAnimationFrame(() => {
      if (!isTopmostDialog(dialogRef.current)) return;
      focusFirst(dialogRef.current!, initialSelector);
    });

    const handleKey = (event: KeyboardEvent) => {
      if (!isTopmostDialog(dialogRef.current)) return;
      if (event.key === "Escape") {
        if (event.defaultPrevented) return;
        if (canCloseRef.current) {
          event.preventDefault();
          cancelRef.current();
        }
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;

      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter(isVisible);

      if (focusable.length === 0) {
        event.preventDefault();
        if (!dialogRef.current.hasAttribute("tabindex")) {
          dialogRef.current.setAttribute("tabindex", "-1");
        }
        dialogRef.current.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      const isInside = dialogRef.current.contains(active);

      if (!isInside) {
        event.preventDefault();
        if (event.shiftKey) {
          last.focus();
        } else {
          first.focus();
        }
        return;
      }

      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    const handleOverlayStackChange = () => {
      requestAnimationFrame(() => {
        if (isTopmostDialog(dialogRef.current)) focusFirst(dialogRef.current!, initialSelector);
      });
    };

    window.addEventListener("keydown", handleKey);
    window.addEventListener(OVERLAY_STACK_EVENT, handleOverlayStackChange);
    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("keydown", handleKey);
      window.removeEventListener(OVERLAY_STACK_EVENT, handleOverlayStackChange);
      const remainingDialogs = modalDialogs().filter((dialog) => dialog !== dialogRef.current);
      const remainingTop = remainingDialogs[remainingDialogs.length - 1];
      if (remainingTop) {
        if (previous && remainingTop.contains(previous)) previous.focus();
        else focusFirst(remainingTop);
      } else if (previous && typeof previous.focus === "function" && document.body.contains(previous)) {
        try {
          previous.focus();
        } catch {
          // ignore if previous element is unmounted or cannot be focused
        }
      }
    };
  }, [initialSelector]);

  return dialogRef;
}
