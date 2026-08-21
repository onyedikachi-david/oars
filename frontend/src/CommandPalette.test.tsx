// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { CommandPalette, type CommandItem } from "./components/CommandPalette";

describe("CommandPalette", () => {
  afterEach(() => {
    cleanup();
  });

  const mockCommands: CommandItem[] = [
    {
      id: "cmd-new-server",
      title: "Add new server",
      subtitle: "Configure SSH credentials",
      category: "Navigation",
      keywords: ["create", "ssh", "connect"],
      run: vi.fn(),
    },
    {
      id: "cmd-scripts",
      title: "Open Script Library",
      subtitle: "View and execute scripts",
      category: "Navigation",
      keywords: ["bash", "terminal", "run"],
      run: vi.fn(),
    },
    {
      id: "cmd-files",
      title: "Open File Manager",
      subtitle: "Browse SFTP and local files",
      category: "Navigation",
      keywords: ["sftp", "explorer"],
      run: vi.fn(),
    },
  ];

  it("renders with WAI-ARIA combobox pattern attributes", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const combobox = screen.getByRole("combobox");
    expect(combobox).toBeTruthy();
    expect(combobox.getAttribute("aria-expanded")).toBe("true");
    expect(combobox.getAttribute("aria-haspopup")).toBe("listbox");
    expect(combobox.getAttribute("aria-autocomplete")).toBe("list");
    expect(combobox.getAttribute("aria-controls")).toBe("cmd-palette-listbox");

    const listbox = screen.getByRole("listbox");
    expect(listbox).toBeTruthy();
    expect(listbox.getAttribute("id")).toBe("cmd-palette-listbox");

    const options = screen.getAllByRole("option");
    expect(options).toHaveLength(3);
    expect(options[0].getAttribute("aria-selected")).toBe("true");
    expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");
  });

  it("navigates options via ArrowDown and ArrowUp updating aria-activedescendant", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const combobox = screen.getByRole("combobox");
    const options = screen.getAllByRole("option");

    expect(options[0].getAttribute("aria-selected")).toBe("true");
    expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");

    fireEvent.keyDown(combobox, { key: "ArrowDown" });
    expect(options[1].getAttribute("aria-selected")).toBe("true");
    expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-1");

    fireEvent.keyDown(combobox, { key: "ArrowDown" });
    expect(options[2].getAttribute("aria-selected")).toBe("true");
    expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-2");

    fireEvent.keyDown(combobox, { key: "ArrowUp" });
    expect(options[1].getAttribute("aria-selected")).toBe("true");
    expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-1");
  });

  it("filters options based on search query", async () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const combobox = screen.getByRole("combobox");
    fireEvent.change(combobox, { target: { value: "script" } });

    const options = screen.getAllByRole("option");
    expect(options).toHaveLength(1);
    expect(options[0].textContent).toContain("Open Script Library");
  });

  it("displays empty state when no commands match", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const combobox = screen.getByRole("combobox");
    fireEvent.change(combobox, { target: { value: "nonexistent query xyz" } });

    expect(screen.queryByRole("option")).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("No matching commands");
  });

  it("executes the selected action and closes on Enter", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const combobox = screen.getByRole("combobox");
    fireEvent.keyDown(combobox, { key: "ArrowDown" }); // Move to cmd-scripts
    fireEvent.keyDown(combobox, { key: "Enter" });

    expect(mockCommands[1].run).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("executes clicked item and closes", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    const options = screen.getAllByRole("option");
    fireEvent.click(options[2]); // cmd-files

    expect(mockCommands[2].run).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes when Escape key is pressed", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={mockCommands} onClose={onClose} />);

    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
