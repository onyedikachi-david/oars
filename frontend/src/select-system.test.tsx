// @vitest-environment jsdom

import { readdirSync, readFileSync } from "node:fs";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { OarsSelect } from "./components/ui/select";

function productionTsxFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) return productionTsxFiles(path);
    if (!entry.name.endsWith(".tsx") || entry.name.endsWith(".test.tsx")) return [];
    return [path];
  });
}

describe("Oars select system", () => {
  it("keeps browser-native selects out of production components", () => {
    const sourceRoot = `${process.cwd()}/src`;
    const violations = productionTsxFiles(sourceRoot)
      .filter((path) => !path.endsWith("/components/ui/select.tsx"))
      .filter((path) => /<select\b/.test(readFileSync(path, "utf8")));

    expect(violations).toEqual([]);
  });

  it("portals its popup outside clipped feature and modal containers", async () => {
    const user = userEvent.setup();
    const onValueChange = vi.fn();
    const { container } = render(
      <div data-testid="clipped-parent" style={{ overflow: "hidden" }}>
        <OarsSelect
          aria-label="Environment"
          value="production"
          onValueChange={onValueChange}
          options={[
            { value: "development", label: "Development" },
            { value: "production", label: "Production" },
          ]}
        />
      </div>,
    );

    await user.click(screen.getByRole("combobox", { name: "Environment" }));

    const popup = screen.getByRole("listbox");
    expect(container.contains(popup)).toBe(false);
    expect(document.body.contains(popup)).toBe(true);

    await user.click(screen.getByRole("option", { name: "Development" }));
    expect(onValueChange).toHaveBeenCalledWith("development");
  });

  it("reserves the indicator column for every option so labels keep the menu width", async () => {
    const user = userEvent.setup();
    render(
      <OarsSelect
        aria-label="Backup server"
        value="production"
        onValueChange={vi.fn()}
        options={[
          { value: "production", label: "Production API — api.internal.example · Connected" },
          { value: "staging", label: "Staging Web — 10.24.8.17 · Connected" },
          { value: "database", label: "Legacy Database — db-01.internal.example · Connected" },
        ]}
      />,
    );

    await user.click(screen.getByRole("combobox", { name: "Backup server" }));

    for (const option of screen.getAllByRole("option", { hidden: true })) {
      expect(option.querySelector(".oars-select-item-indicator")).not.toBeNull();
      expect(option.querySelector(".oars-select-item-text")?.textContent).not.toMatch(/…$/);
    }
  });

  it("supports keyboard selection and disabled triggers", async () => {
    const user = userEvent.setup();
    const onValueChange = vi.fn();
    render(
      <>
        <OarsSelect
          aria-label="Lines"
          value="200"
          onValueChange={onValueChange}
          options={[{ value: "200", label: "200 lines" }, { value: "500", label: "500 lines" }]}
        />
        <OarsSelect
          aria-label="Locked selector"
          value="locked"
          onValueChange={vi.fn()}
          options={[{ value: "locked", label: "Locked" }]}
          disabled
        />
      </>,
    );

    const trigger = screen.getByRole("combobox", { name: "Lines" });
    trigger.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("option", { name: "200 lines" });
    await user.keyboard("{ArrowDown}");
    await user.keyboard("{Enter}");
    expect(onValueChange).toHaveBeenCalledWith("500");
    expect((screen.getByRole("combobox", { name: "Locked selector" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
