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

  it("expires after 30 s and deletes cached entry", () => {
    cache.set("prod", "u:/expire-me", listing, 1000);
    expect(cache.get("prod", "u:/expire-me", 1000 + DIR_CACHE_TTL_MS + 1)).toBeNull();
    // Subsequent get is also null
    expect(cache.get("prod", "u:/expire-me", 1000 + DIR_CACHE_TTL_MS + 2)).toBeNull();
  });

  it("scopes hits by server and path", () => {
    cache.set("prod", "u:/etc", listing, 5000);
    expect(cache.get("staging", "u:/etc", 6000)).toBeNull();
    expect(cache.get("prod", "u:/var", 6000)).toBeNull();
    expect(cache.get("prod", "u:/etc", 6000)).not.toBeNull();
  });

  it("invalidates specific pathKey or all keys for a server", () => {
    const c = new DirCache();
    c.set("prod", "u:/var/www", listing, 1000);
    c.set("prod", "u:/etc", listing, 1000);
    c.set("staging", "u:/var/www", listing, 1000);

    // Invalidate specific path
    c.invalidate("prod", "u:/var/www");
    expect(c.get("prod", "u:/var/www", 2000)).toBeNull();
    expect(c.get("prod", "u:/etc", 2000)).not.toBeNull();
    expect(c.get("staging", "u:/var/www", 2000)).not.toBeNull();

    // Invalidate all paths for prod
    c.invalidate("prod");
    expect(c.get("prod", "u:/etc", 2000)).toBeNull();
    expect(c.get("staging", "u:/var/www", 2000)).not.toBeNull();
  });

  it("clears entire cache", () => {
    const c = new DirCache();
    c.set("prod", "u:/1", listing, 1000);
    c.set("staging", "u:/2", listing, 1000);
    c.clear();
    expect(c.get("prod", "u:/1", 1000)).toBeNull();
    expect(c.get("staging", "u:/2", 1000)).toBeNull();
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

  it("range without an anchor or with undisplayed target degrades to a plain click", () => {
    const sel1 = selectionRange(emptySelection(), displayed, "b");
    expect(sel1.keys).toEqual(["b"]);

    const withAnchor = selectionSelectOnly(emptySelection(), "b");
    const sel2 = selectionRange(withAnchor, displayed, "undisplayed_key");
    expect(sel2.keys).toEqual(["undisplayed_key"]);
    expect(sel2.anchor).toBe("undisplayed_key");
  });

  it("select-all, add, and clear behave", () => {
    const all = selectionAll(displayed);
    expect(all.keys).toHaveLength(5);
    expect(all.anchor).toBe("e");
    expect(selectionHas(all, "c")).toBe(true);

    const emptyAll = selectionAll([]);
    expect(emptyAll.keys).toEqual([]);
    expect(emptyAll.anchor).toBeNull();

    const baseSel = emptySelection();
    const added = selectionAdd(baseSel, "x");
    expect(added.keys).toEqual(["x"]);

    // Adding existing key returns same selection reference
    const duplicateAdd = selectionAdd(added, "x");
    expect(duplicateAdd).toBe(added);

    expect(selectionClear()).toEqual({ keys: [], anchor: null });
  });
});

describe("permission strings", () => {
  it("produces valid octal defaults", () => {
    expect(permissionStringToOctal("-rw-r--r--")).toBe("644");
    expect(permissionStringToOctal("drwxr-xr-x")).toBe("755");
    expect(permissionStringToOctal("-rwxrwxrwx")).toBe("777");
  });

  it("handles empty or invalid length strings", () => {
    expect(permissionStringToOctal("")).toBe("");
    expect(permissionStringToOctal("rwx")).toBe("");
    expect(permissionStringToOctal("12345678")).toBe("");
  });

  it("handles SUID, SGID, and Sticky special bits", () => {
    // SUID with s / S
    expect(permissionStringToOctal("-rwsr-xr-x")).toBe("4755");
    expect(permissionStringToOctal("-rwSr-xr-x")).toBe("4755");
    expect(permissionStringToOctal("-rwSr--r--")).toBe("4744");

    // SGID with s / S
    expect(permissionStringToOctal("-rwxr-sr-x")).toBe("2755");
    expect(permissionStringToOctal("-rwxr-Sr-x")).toBe("2755");
    expect(permissionStringToOctal("-rwxr-Sr--")).toBe("2754");

    // Sticky with t / T
    expect(permissionStringToOctal("drwxrwxrwt")).toBe("1777");
    expect(permissionStringToOctal("drwxrwxrwT")).toBe("1777");

    // Combined special bits
    expect(permissionStringToOctal("-rwsr-sr-t")).toBe("7755");
    expect(permissionStringToOctal("-rwSr-Sr-T")).toBe("7755");
  });
});
