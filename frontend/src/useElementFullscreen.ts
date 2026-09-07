import { useCallback, useEffect, useRef, useState } from "react";

/** Keeps the existing element (and its live remote connection) in place. */
export function useElementFullscreen(sessionKey: string) {
  const ref = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const previousFocus = useRef<HTMLElement | null>(null);
  const exitRef = useRef<() => void>(() => {});

  const toggle = useCallback(async (forceExit = false) => {
    const element = ref.current;
    if (!element) return;
    const doc = element.ownerDocument;
    const exiting = doc.fullscreenElement === element;
    if (busy && !(forceExit && exiting)) return;
    setError(null);
    if (!exiting && (!element.requestFullscreen || doc.fullscreenEnabled === false)) {
      setError("VNC full screen is unavailable in this WebView. You can still use the window's full-screen control.");
      return;
    }
    if (doc.fullscreenElement && !exiting) {
      setError("Exit the current full-screen view first.");
      return;
    }
    const request = ++generation.current;
    setBusy(true);
    if (!exiting) previousFocus.current = doc.activeElement instanceof HTMLElement ? doc.activeElement : null;
    try {
      // Keep the request in the click/keyboard gesture; do not await other work first.
      if (exiting) await doc.exitFullscreen();
      else await element.requestFullscreen();
      if (request !== generation.current) {
        if (!exiting && doc.fullscreenElement === element) await doc.exitFullscreen();
        return;
      }
      setActive(doc.fullscreenElement === element);
    } catch (cause) {
      if (request === generation.current) {
        setError(`Could not ${exiting ? "exit" : "open"} full screen: ${cause instanceof Error ? cause.message : String(cause)}`);
      }
    } finally {
      if (request === generation.current) setBusy(false);
    }
  }, [busy, sessionKey]);
  exitRef.current = () => { if (ref.current?.ownerDocument.fullscreenElement === ref.current) void toggle(true); };

  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const doc = element.ownerDocument;
    let owned = doc.fullscreenElement === element;
    let suppressEscapeUp = false;
    setActive(owned);
    setBusy(false);
    setError(null);
    const synchronize = () => {
      const next = doc.fullscreenElement === element;
      setActive(next);
      if (owned && !next && previousFocus.current?.isConnected) previousFocus.current.focus();
      owned = next;
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (event.type === "keyup" && suppressEscapeUp) {
        suppressEscapeUp = false;
        event.preventDefault();
        event.stopImmediatePropagation();
        return;
      }
      if (event.type !== "keydown" || doc.fullscreenElement !== element) return;
      // Let a focused dialog handle DOM Escape events. The native WebView may
      // exit full screen before dispatching that key to the page.
      if (element.querySelector('[role="dialog"][aria-modal="true"]')) return;
      suppressEscapeUp = true;
      event.preventDefault();
      event.stopImmediatePropagation();
      exitRef.current();
    };
    doc.addEventListener("fullscreenchange", synchronize);
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("keyup", onKey, true);

    // Tabs stay mounted in Oars. Leave full screen if its pane is hidden.
    const ancestors: HTMLElement[] = [];
    for (let parent = element.parentElement; parent; parent = parent.parentElement) ancestors.push(parent);
    const observer = new MutationObserver(() => {
      if (doc.fullscreenElement !== element) return;
      if (ancestors.some(parent => parent.hidden || getComputedStyle(parent).display === "none")) exitRef.current();
    });
    for (const parent of ancestors) observer.observe(parent, { attributes: true, attributeFilter: ["class", "style", "hidden"] });
    return () => {
      ++generation.current;
      doc.removeEventListener("fullscreenchange", synchronize);
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("keyup", onKey, true);
      observer.disconnect();
      if (doc.fullscreenElement === element) void doc.exitFullscreen().catch(() => {});
    };
  }, [sessionKey]);

  return { ref, active, busy, error, toggle };
}
