import { describe, expect, it } from "vitest";
import {
  DIR_CACHE_TTL_MS,
  DirCache,
  emptySelection,
  emptySnapshot,
  isCurrentDirRequest,
  permissionStringToOctal,
  selectionAdd,
  selectionAll,
  selectionClear,
  selectionHas,
  selectionRange,
  selectionSelectOnly,
  selectionToggle,
} from "./file-state";
import { rpFromUtf8 } from "./sftp-path";

describe("source-bound directory requests", () => {
  const token = { generation: 3, serverId: "prod", pathKey: "u:/var/www" };

  it("accepts only the current generation, server, and path", () => {
    expect(isCurrentDirRequest(token, 3, "prod", "u:/var/www")).toBe(true);
    expect(isCurrentDirRequest(token, 4, "prod", "u:/var/www")).toBe(false);
    expect(isCurrentDirRequest(token, 3, "staging", "u:/var/www")).toBe(false);
    expect(isCurrentDirRequest(token, 3, "prod", "u:/etc")).toBe(false);
  });

  it("produces a stable path key from the raw identity", () => {
    expect(emptySnapshot("prod", rpFromUtf8("/etc")).pathKey).toBe("u:/etc");
  });
});

describe("directory cache", () => {
  const cache = new DirCache();
  const listing = { entries: [], truncated: false };

  it("serves a hit within the 30 s TTL", () => {
    cache.set("prod", "u:/etc", listing, 1000);
    expect(cache.get("prod", "u:/etc", 1000 + DIR_CACHE_TTL_MS - 1)).not.toBeNull();
  });

  it("expires after 30 s", () => {
    expect(cache.get("prod", "u:/etc", 1000 + DIR_CACHE_TTL_MS + 1)).toBeNull();
  });

  it("scopes hits by server and path", () => {
    cache.set("prod", "u:/etc", listing, 5000);
    expect(cache.get("staging", "u:/etc", 6000)).toBeNull();
    expect(cache.get("prod", "u:/var", 6000)).toBeNull();
    expect(cache.get("prod", "u:/etc", 6000)).not.toBeNull();
  });
});

describe("selection model", () => {
  const displayed = ["a", "b", "c", "d", "e"];

  it("plain click selects exactly one entry and anchors it", () => {
    const sel = selectionSelectOnly(emptySelection(), "c");
    expect(sel.keys).toEqual(["c"]);
    expect(sel.anchor).toBe("c");
  });

  it("modified click toggles membership without losing the anchor", () => {
    let sel = selectionSelectOnly(emptySelection(), "a");
    sel = selectionToggle(sel, "c");
    expect(sel.keys).toEqual(["a", "c"]);
    sel = selectionToggle(sel, "a");
    expect(sel.keys).toEqual(["c"]);
  });

  it("shift-click selects the displayed range from the anchor", () => {
    let sel = selectionSelectOnly(emptySelection(), "b");
    sel = selectionRange(sel, displayed, "d");
    expect(sel.keys.sort()).toEqual(["b", "c", "d"]);
  });

  it("shift-click ranges backwards and merges with prior selection", () => {
    let sel = selectionSelectOnly(emptySelection(), "d");
    sel = selectionRange(sel, displayed, "a");
    expect(sel.keys.sort()).toEqual(["a", "b", "c", "d"]);
  });

  it("range without an anchor degrades to a plain click", () => {
    const sel = selectionRange(emptySelection(), displayed, "b");
    expect(sel.keys).toEqual(["b"]);
  });

  it("select-all, add, and clear behave", () => {
    const all = selectionAll(displayed);
    expect(all.keys).toHaveLength(5);
    expect(selectionHas(all, "c")).toBe(true);
    expect(selectionAdd(emptySelection(), "x").keys).toEqual(["x"]);
    expect(selectionAdd(emptySelection(), "x").keys).toEqual(["x"]);
    expect(selectionClear()).toEqual({ keys: [], anchor: null });
  });
});

describe("permission strings", () => {
  it("produces valid octal defaults", () => {
    expect(permissionStringToOctal("-rw-r--r--")).toBe("644");
    expect(permissionStringToOctal("drwxr-xr-x")).toBe("755");
    expect(permissionStringToOctal("-rwsr-xr-x")).toBe("4755");
  });
});
