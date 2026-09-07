import { beforeEach, describe, expect, it } from "vitest";
import { appShortcut } from "./keyboard";
import { parsePaletteQuery, rankCommands, readPaletteState, savePaletteState } from "./palette";
const key = (key: string, modifiers = {}) => ({ key, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false, ...modifiers });
describe("terminal-safe shortcut map", () => {
  it("reserves Linux shell editing keys and only intercepts specified app chords", () => {
    for (const char of ["k", "w", "t", "l", "c", "v", "r"]) expect(appShortcut(key(char, { ctrlKey: true }), false, true)).toBeNull();
    expect(appShortcut(key("P", { ctrlKey: true, shiftKey: true }), false, true)).toBe("palette");
    expect(appShortcut(key("T", { ctrlKey: true, shiftKey: true }), false, true)).toBe("new");
    expect(appShortcut(key("R", { ctrlKey: true, shiftKey: true }), false, true)).toBe("reopen");
    expect(appShortcut(key("W", { ctrlKey: true, shiftKey: true }), false, true)).toBe("close");
    expect(appShortcut(key("9", { altKey: true }), false, true)).toBe("tab-9");
  });
  it("distinguishes macOS new/reopen and leaves terminal log-search chords alone", () => {
    expect(appShortcut(key("k", { metaKey: true }), true, true)).toBe("palette");
    expect(appShortcut(key("t", { metaKey: true }), true)).toBe("new");
    expect(appShortcut(key("T", { metaKey: true, shiftKey: true }), true)).toBe("reopen");
    expect(appShortcut(key("l", { metaKey: true }), true, true)).toBeNull();
    expect(appShortcut(key("l", { metaKey: true }), true)).toBe("logs");
    expect(appShortcut(key(",", { metaKey: true }), true)).toBe("settings");
    expect(appShortcut(key("e", { metaKey: true }), true)).toBe("files");
  });
});
describe("palette query and ranking", () => {
  beforeEach(() => localStorage.clear());
  const commands = [{ id: "a", title: "Open production", mode: "server" as const }, { id: "b", title: "Production", mode: "server" as const }, { id: "c", title: "Provision demo", mode: "action" as const }, { id: "d", title: "Deploy", mode: "script" as const }, { id: "e", title: "uname -a", mode: "history" as const }];
  it("parses all four modes and permits whitespace", () => {
    for (const [prefix, mode] of [[">", "action"], ["@", "server"], ["#", "script"], ["/", "history"]]) expect(parsePaletteQuery(` ${prefix} PRO `)).toEqual({ mode, text: "pro" });
    expect(rankCommands(commands, "#").map(item => item.id)).toEqual(["d"]);
    expect(rankCommands(commands, "/").map(item => item.id)).toEqual(["e"]);
  });
  it("ranks exact and prefix matches before substrings and supports subsequences", () => {
    expect(rankCommands(commands, "@production").map(item => item.id)).toEqual(["b", "a"]);
    expect(rankCommands(commands, "@prdctn").map(item => item.id)).toContain("b");
    expect(rankCommands(commands, "@zzzz")).toHaveLength(0);
  });
  it("persists only stable recent IDs and validates malformed storage", () => {
    savePaletteState({ recentIds: ["b"], query: "@pro" }); expect(readPaletteState()).toEqual({ recentIds: ["b"], query: "@pro" });
    expect(rankCommands(commands, "", ["e"])[0].id).toBe("e");
    localStorage.setItem("oars.palette", "null"); expect(readPaletteState()).toEqual({ recentIds: [], query: "" });
  });
  it("does not truncate matches after the first 20 entries", () => {
    const large = Array.from({ length: 250 }, (_, i) => ({ id: `${i}`, title: `Server ${i}`, mode: "server" as const }));
    expect(rankCommands(large, "@server")).toHaveLength(250); expect(rankCommands(large, "@server 249")[0].id).toBe("249");
  });
});
