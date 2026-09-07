import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { parsePaletteQuery, rankCommands, readPaletteState, savePaletteState, type PaletteMode } from "../palette";
import { Search } from "lucide-react";
import { ApplicationOverlay } from "./ApplicationPortal";
import { useModalFocus } from "./useModalFocus";

export interface CommandItem {
  id: string;
  title: string;
  subtitle?: string;
  category?: string;
  keywords?: string[];
  mode?: PaletteMode;
  danger?: boolean;
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
  const [internalQuery, setInternalQuery] = useState(() => readPaletteState().query);
  const [recentIds, setRecentIds] = useState(() => readPaletteState().recentIds);
  const [armedId, setArmedId] = useState<string | null>(null);
  const currentQuery = externalQuery !== undefined ? externalQuery : internalQuery;

  const normalizedCommands = useMemo<CommandItem[]>(() => {
    const source = commands ?? items?.map((item, index) => ({ id: `item-${index}`, title: item.label, category: item.group, run: item.action })) ?? [];
    const ranked = rankCommands(source, currentQuery, recentIds);
    if (parsePaletteQuery(currentQuery).text) return ranked;
    const grouped = new Map<string, CommandItem[]>();
    for (const command of ranked) {
      const group = !currentQuery.trim() && recentIds.includes(command.id) ? "Recent" : command.category ?? "Actions";
      const entries = grouped.get(group) ?? []; entries.push(command); grouped.set(group, entries);
    }
    return [...grouped.values()].flat();
  }, [commands, items, currentQuery, recentIds]);

  const execute = (command: CommandItem) => {
    if (command.danger && armedId !== command.id) { setArmedId(command.id); return; }
    const recent = [command.id, ...recentIds.filter(id => id !== command.id)].slice(0, 5);
    setRecentIds(recent); savePaletteState({ recentIds: recent, query: currentQuery });
    setArmedId(null); onClose(); command.run();
  };
  useEffect(() => { setArmedId(null); }, [currentQuery, isOpen]);

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
    setSelectedIndex(0);
    setArmedId(null);
    savePaletteState({ recentIds, query: val });
    if (onQueryChange) {
      onQueryChange(val);
    } else {
      setInternalQuery(val);
    }
  };

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== "Enter") setArmedId(null);
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
        execute(target);
      }
    }
  };

  const groupFor = (command: CommandItem) => !currentQuery.trim() && recentIds.includes(command.id) ? "Recent" : command.category ?? "Actions";
  const highlight = (title: string) => {
    const query = parsePaletteQuery(currentQuery).text;
    if (!query) return title;
    const positions = new Set<number>(); let position = 0;
    for (const char of query) { const index = title.toLowerCase().indexOf(char, position); if (index < 0) return title; positions.add(index); position = index + 1; }
    return [...title].map((char, index) => positions.has(index) ? <mark key={index} style={{ color: "inherit", background: "transparent", fontWeight: 750 }}>{char}</mark> : char);
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
            placeholder="Search · > actions · @ servers · # scripts · / history"
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
            maxHeight: 360,
          }}
        >
          {normalizedCommands.map((cmd, i) => {
            const isSelected = i === selectedIndex;
            return (
              <Fragment key={cmd.id || i}>
              {(i === 0 || groupFor(normalizedCommands[i - 1]) !== groupFor(cmd)) && <div role="presentation" className="muted" style={{ padding: "6px 12px 2px", fontSize: 11 }}>{groupFor(cmd)}</div>}
              <button
                id={`cmd-palette-opt-${i}`}
                type="button"
                role="option"
                aria-selected={isSelected}
                onClick={() => {
                  execute(cmd);
                }}
                onMouseEnter={() => { setSelectedIndex(i); setArmedId(null); }}
                style={{
                  textAlign: "left",
                  background: isSelected ? "var(--accent)" : "transparent",
                  border: isSelected
                    ? "1px solid var(--border)"
                    : "1px solid transparent",
                  color: cmd.danger ? "var(--destructive)" : isSelected ? "var(--primary)" : "var(--foreground)",
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
                  <div style={{ fontWeight: 500 }}>{highlight(cmd.title)}{armedId === cmd.id ? " — press Enter again to confirm" : ""}</div>
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
              </Fragment>
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
        <div className="muted" style={{ padding: "8px 16px", fontSize: 11 }}>↑↓ navigate · Enter open · Escape close</div>
      </div>
    </ApplicationOverlay>
  );
}
