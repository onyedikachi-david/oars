import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { ApplicationOverlay } from "./ApplicationPortal";
import { useModalFocus } from "./useModalFocus";

export interface CommandItem {
  id: string;
  title: string;
  subtitle?: string;
  category?: string;
  keywords?: string[];
  run: () => void;
}

export interface PaletteItem {
  label: string;
  action: () => void;
  group?: string;
}

export interface CommandPaletteProps {
  isOpen?: boolean;
  onClose: () => void;
  commands?: CommandItem[];
  items?: PaletteItem[];
  query?: string;
  onQueryChange?: (query: string) => void;
}

export function CommandPalette({
  isOpen = true,
  onClose,
  commands,
  items,
  query: externalQuery,
  onQueryChange,
}: CommandPaletteProps) {
  const [internalQuery, setInternalQuery] = useState("");
  const currentQuery = externalQuery !== undefined ? externalQuery : internalQuery;

  const normalizedCommands = useMemo<CommandItem[]>(() => {
    if (commands) {
      const q = currentQuery.trim().toLowerCase();
      if (!q) return commands;
      return commands.filter((cmd) => {
        if (cmd.title.toLowerCase().includes(q)) return true;
        if (cmd.subtitle?.toLowerCase().includes(q)) return true;
        if (cmd.category?.toLowerCase().includes(q)) return true;
        if (cmd.keywords?.some((k) => k.toLowerCase().includes(q))) return true;
        return false;
      });
    }
    if (items) {
      return items.map((it, idx) => ({
        id: `item-${idx}`,
        title: it.label,
        subtitle: undefined,
        category: it.group,
        run: it.action,
      }));
    }
    return [];
  }, [commands, items, currentQuery]);

  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const dialogRef = useModalFocus(onClose, "input", isOpen);

  useEffect(() => {
    setSelectedIndex((prev) => {
      if (normalizedCommands.length === 0) return 0;
      if (prev >= normalizedCommands.length) return 0;
      return prev;
    });
  }, [normalizedCommands]);

  useEffect(() => {
    if (!listRef.current) return;
    const activeEl = listRef.current.querySelector<HTMLElement>(
      `#cmd-palette-opt-${selectedIndex}`,
    );
    if (activeEl && typeof activeEl.scrollIntoView === "function") {
      activeEl.scrollIntoView({ block: "nearest" });
    }
  }, [selectedIndex]);

  if (!isOpen) return null;

  const handleQueryChange = (val: string) => {
    if (onQueryChange) {
      onQueryChange(val);
    } else {
      setInternalQuery(val);
    }
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (normalizedCommands.length > 0) {
        setSelectedIndex((prev) => (prev + 1) % normalizedCommands.length);
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (normalizedCommands.length > 0) {
        setSelectedIndex((prev) => (prev - 1 + normalizedCommands.length) % normalizedCommands.length);
      }
    } else if (e.key === "Home") {
      e.preventDefault();
      setSelectedIndex(0);
    } else if (e.key === "End") {
      e.preventDefault();
      if (normalizedCommands.length > 0) {
        setSelectedIndex(normalizedCommands.length - 1);
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = normalizedCommands[selectedIndex];
      if (target) {
        target.run();
        onClose();
      }
    }
  };

  const activeDescendantId =
    normalizedCommands.length > 0 && selectedIndex >= 0 && selectedIndex < normalizedCommands.length
      ? `cmd-palette-opt-${selectedIndex}`
      : undefined;

  return (
    <ApplicationOverlay
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="oars-modal oars-command-palette"
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
        style={{
          width: 580,
          maxHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          padding: 0,
          overflow: "hidden",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="command-palette-title" className="sr-only">
          Command Palette
        </h2>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "12px 14px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <Search size={16} className="text-muted-foreground" aria-hidden="true" />
          <input
            ref={inputRef}
            autoFocus
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-haspopup="listbox"
            aria-autocomplete="list"
            aria-controls="cmd-palette-listbox"
            aria-activedescendant={activeDescendantId}
            aria-label="Type a command or search"
            placeholder="Type a command or search…"
            value={currentQuery}
            onChange={(e) => handleQueryChange(e.target.value)}
            onKeyDown={handleInputKeyDown}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              color: "var(--foreground)",
              fontSize: 13,
              outline: "none",
            }}
          />
        </div>
        <div
          ref={listRef}
          id="cmd-palette-listbox"
          role="listbox"
          aria-label="Commands"
          style={{
            overflowY: "auto",
            padding: 8,
            display: "grid",
            gap: 2,
            maxHeight: 380,
          }}
        >
          {normalizedCommands.map((cmd, i) => {
            const isSelected = i === selectedIndex;
            return (
              <button
                key={cmd.id || i}
                id={`cmd-palette-opt-${i}`}
                type="button"
                role="option"
                aria-selected={isSelected}
                onClick={() => {
                  cmd.run();
                  onClose();
                }}
                onMouseEnter={() => setSelectedIndex(i)}
                style={{
                  textAlign: "left",
                  background: isSelected ? "var(--accent)" : "transparent",
                  border: isSelected
                    ? "1px solid var(--border)"
                    : "1px solid transparent",
                  color: isSelected ? "var(--primary)" : "var(--foreground)",
                  borderRadius: 6,
                  padding: "8px 12px",
                  fontSize: 12,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  transition: "background 0.1s ease",
                }}
              >
                <div>
                  <div style={{ fontWeight: 500 }}>{cmd.title}</div>
                  {cmd.subtitle && (
                    <div className="muted" style={{ fontSize: 11 }}>
                      {cmd.subtitle}
                    </div>
                  )}
                </div>
                {cmd.category && (
                  <span
                    className="muted"
                    style={{ fontSize: 10, textTransform: "uppercase" }}
                  >
                    {cmd.category}
                  </span>
                )}
              </button>
            );
          })}
          {normalizedCommands.length === 0 && (
            <div
              role="status"
              className="muted"
              style={{
                padding: "24px 12px",
                textAlign: "center",
                fontSize: 12,
              }}
            >
              No matching commands
            </div>
          )}
        </div>
      </div>
    </ApplicationOverlay>
  );
}
