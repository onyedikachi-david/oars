import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { Check, Columns3, LayoutGrid, PanelTop, Pin } from "lucide-react";
import { Button } from "./ui/button";
import { ApplicationPortal } from "./ApplicationPortal";
import {
  WORKSPACE_LAYOUT_VARIANTS,
  type WorkspaceLayoutVariant,
} from "../workspace-layout";

const VARIANT_ICONS = {
  balanced: LayoutGrid,
  columns: Columns3,
  focus: PanelTop,
} as const;

const MENU_WIDTH = 286;
const MENU_GAP = 8;
const VIEWPORT_MARGIN = 12;
const COMPACT_BREAKPOINT = 760;

export function WorkspaceLayoutPicker({
  value,
  defaultValue,
  onChange,
  onSaveDefault,
}: {
  value: WorkspaceLayoutVariant;
  defaultValue: WorkspaceLayoutVariant;
  onChange: (value: WorkspaceLayoutVariant) => void;
  onSaveDefault: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [menuStyle, setMenuStyle] = useState<CSSProperties>({});
  const [placement, setPlacement] = useState<"top" | "bottom">("bottom");
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const closeMenu = useCallback((restoreFocus = false) => {
    setOpen(false);
    if (restoreFocus) triggerRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!rootRef.current?.contains(target) && !menuRef.current?.contains(target)) closeMenu();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeMenu(true);
      }
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [closeMenu, open]);

  useLayoutEffect(() => {
    if (!open) return;

    const positionMenu = () => {
      const trigger = triggerRef.current;
      if (!trigger) return;
      const rect = trigger.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      if (viewportWidth <= COMPACT_BREAKPOINT) {
        setPlacement("bottom");
        setMenuStyle({
          top: "auto",
          right: VIEWPORT_MARGIN,
          bottom: VIEWPORT_MARGIN,
          left: VIEWPORT_MARGIN,
          width: "auto",
          maxHeight: `calc(100dvh - ${VIEWPORT_MARGIN * 2}px)`,
        });
        return;
      }

      const menuHeight = menuRef.current?.offsetHeight || 286;
      const roomBelow = viewportHeight - rect.bottom - VIEWPORT_MARGIN;
      const roomAbove = rect.top - VIEWPORT_MARGIN;
      const openAbove = roomBelow < menuHeight + MENU_GAP && roomAbove > roomBelow;
      const left = Math.min(
        Math.max(VIEWPORT_MARGIN, rect.right - MENU_WIDTH),
        Math.max(VIEWPORT_MARGIN, viewportWidth - MENU_WIDTH - VIEWPORT_MARGIN),
      );
      const top = openAbove
        ? Math.max(VIEWPORT_MARGIN, rect.top - MENU_GAP - menuHeight)
        : Math.min(rect.bottom + MENU_GAP, viewportHeight - VIEWPORT_MARGIN);

      setPlacement(openAbove ? "top" : "bottom");
      setMenuStyle({
        top,
        right: "auto",
        bottom: "auto",
        left,
        width: MENU_WIDTH,
        maxHeight: openAbove
          ? Math.max(120, roomAbove - MENU_GAP)
          : Math.max(120, roomBelow - MENU_GAP),
      });
    };

    positionMenu();
    const frameId = requestAnimationFrame(() => {
      positionMenu();
      menuRef.current
        ?.querySelector<HTMLElement>('[role="menuitemradio"][aria-checked="true"]')
        ?.focus();
    });
    window.addEventListener("resize", positionMenu);
    window.addEventListener("scroll", positionMenu, true);
    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("resize", positionMenu);
      window.removeEventListener("scroll", positionMenu, true);
    };
  }, [open]);

  const handleMenuKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>('[role^="menuitem"]:not([disabled])') ?? [],
    );
    if (items.length === 0) return;
    const currentIndex = items.indexOf(document.activeElement as HTMLButtonElement);
    let nextIndex: number | null = null;
    if (event.key === "ArrowDown") nextIndex = (currentIndex + 1 + items.length) % items.length;
    if (event.key === "ArrowUp") nextIndex = (currentIndex - 1 + items.length) % items.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = items.length - 1;
    if (event.key === "Tab") closeMenu();
    if (nextIndex !== null) {
      event.preventDefault();
      items[nextIndex].focus();
    }
  };

  return (
    <div className="workspace-layout-picker" ref={rootRef}>
      <Button
        ref={triggerRef}
        variant="ghost"
        size="icon-sm"
        aria-label="Choose workspace layout"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        title="Workspace layout"
        onClick={() => setOpen((current) => !current)}
      >
        <LayoutGrid />
      </Button>
      {open && (
        <ApplicationPortal>
          <div
            ref={menuRef}
            id={menuId}
            className="workspace-layout-menu"
            role="menu"
            aria-label="Workspace layout"
            data-placement={placement}
            style={menuStyle}
            onKeyDown={handleMenuKeyDown}
          >
            <div className="workspace-layout-menu-heading">
              <strong>Workspace layout</strong>
              <span>Drag any pane header to rearrange it.</span>
            </div>
            {WORKSPACE_LAYOUT_VARIANTS.map((variant) => {
              const Icon = VARIANT_ICONS[variant.id];
              return (
                <button
                  type="button"
                  role="menuitemradio"
                  aria-checked={value === variant.id}
                  className={value === variant.id ? "is-selected" : ""}
                  key={variant.id}
                  onClick={() => {
                    onChange(variant.id);
                    closeMenu(true);
                  }}
                >
                  <Icon aria-hidden />
                  <span>
                    <strong>{variant.label}</strong>
                    <small>{variant.description}</small>
                  </span>
                  {value === variant.id && <Check aria-hidden />}
                </button>
              );
            })}
            <button
              type="button"
              role="menuitem"
              className="workspace-layout-default"
              disabled={value === defaultValue}
              onClick={() => {
                onSaveDefault();
                closeMenu(true);
              }}
            >
              <Pin aria-hidden />
              <span>
                <strong>{value === defaultValue ? "Current default" : "Use as default"}</strong>
                <small>Apply this layout to new workspaces.</small>
              </span>
            </button>
          </div>
        </ApplicationPortal>
      )}
    </div>
  );
}
