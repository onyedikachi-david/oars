// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AI_PREVIEW_MODES, readAiPreviewMode } from "./ai-preview";

afterEach(() => {
  delete document.documentElement.dataset.previewVariant;
  window.history.replaceState({}, "", "/");
});

describe("AI preview modes", () => {
  it("recognizes every frozen Spec 11 fixture only on the preview page", () => {
    document.documentElement.dataset.previewVariant = "baseline";
    for (const mode of AI_PREVIEW_MODES) {
      window.history.replaceState({}, "", `/?ai=${mode}`);
      expect(readAiPreviewMode()).toBe(mode);
    }

    window.history.replaceState({}, "", "/?ai=legacy-config");
    expect(readAiPreviewMode()).toBeNull();
    delete document.documentElement.dataset.previewVariant;
    window.history.replaceState({}, "", "/?ai=streaming");
    expect(readAiPreviewMode()).toBeNull();
  });

  it("keeps the preview bridge fixture list aligned with the typed client list", () => {
    const html = readFileSync(resolve(process.cwd(), "preview.html"), "utf8");
    const match = html.match(/const AI_PREVIEW_MODES = new Set\(\[([\s\S]*?)\]\);/);
    expect(match).not.toBeNull();
    const htmlModes = [...match![1].matchAll(/"([a-z][a-z-]+)"/g)].map((item) => item[1]);
    expect(htmlModes).toEqual([...AI_PREVIEW_MODES]);
  });
});
