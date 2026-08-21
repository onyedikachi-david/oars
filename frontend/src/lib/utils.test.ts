import { describe, expect, it } from "vitest";
import { cn } from "./utils";

describe("lib/utils - cn", () => {
  it("joins multiple string class names", () => {
    expect(cn("px-4", "py-2", "rounded")).toBe("px-4 py-2 rounded");
  });

  it("handles conditional class values", () => {
    const isActive = true;
    const isDisabled = false;
    expect(cn("base-btn", isActive && "btn-active", isDisabled && "btn-disabled")).toBe("base-btn btn-active");
  });

  it("filters out falsy, undefined, and null values", () => {
    expect(cn("visible", null, undefined, false, "")).toBe("visible");
  });

  it("resolves Tailwind CSS conflicts by taking the latter class", () => {
    expect(cn("p-4", "p-2")).toBe("p-2");
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
    expect(cn("bg-red-500 text-white", "bg-black")).toBe("text-white bg-black");
  });

  it("supports array and object syntax from clsx", () => {
    expect(cn(["btn", "btn-lg"], { "is-loading": true, "is-hidden": false })).toBe("btn btn-lg is-loading");
  });
});
