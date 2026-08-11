import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  entryHidden,
  entryIsDot,
  entryKey,
  entryNameBytes,
  rpBasename,
  rpBreadcrumbPaths,
  rpBytes,
  rpDisplay,
  rpFromBytes,
  rpFromUtf8,
  rpIsRoot,
  rpJoin,
  rpParent,
  rpSerialize,
  rpSplit,
  rpStem,
  ROOT,
  utf8ToBytes,
  validateLeafName,
} from "./sftp-path";
import type { RemotePath, SftpEntry } from "./types";

describe("raw path encoding", () => {
  it("encodes valid UTF-8 names as the utf8 form", () => {
    expect(rpFromBytes(utf8ToBytes("nginx.conf"))).toEqual({ utf8: "nginx.conf" });
    expect(rpFromUtf8("nginx.conf")).toEqual({ utf8: "nginx.conf" });
  });

  it("encodes non-UTF-8 names as the base64 form, preserving bytes", () => {
    // 0xff 0xfe are not valid UTF-8.
    const raw = new Uint8Array([0xff, 0xfe, 0x2e, 0x74, 0x78, 0x74]);
    const rp = rpFromBytes(raw);
    expect(rp.utf8).toBeUndefined();
    expect(rp.base64).toBeDefined();
    expect(Array.from(rpBytes(rp))).toEqual([0xff, 0xfe, 0x2e, 0x74, 0x78, 0x74]);
    expect(base64ToBytes(rp.base64!)).toEqual(raw);
  });

  it("base64 round-trips arbitrary bytes", () => {
    const raw = new Uint8Array([0, 1, 2, 0x80, 0xff, 0x41]);
    expect(Array.from(base64ToBytes(bytesToBase64(raw)))).toEqual(Array.from(raw));
  });

  it("serializes identical bytes to the same identity key", () => {
    expect(rpSerialize({ utf8: "a/b" })).toBe("u:a/b");
    const raw = new Uint8Array([0xff, 0xfe]);
    expect(rpSerialize(rpFromBytes(raw))).toBe(`b64:${bytesToBase64(raw)}`);
    // The same raw bytes encoded two ways must collide.
    expect(rpSerialize(rpFromBytes(utf8ToBytes("x")))).toBe(rpSerialize(rpFromUtf8("x")));
  });

  it("displays non-UTF-8 names with replacement characters, never raw bytes", () => {
    const rp = rpFromBytes(new Uint8Array([0xff, 0xfe, 0x2e, 0x74, 0x78, 0x74]));
    expect(rpDisplay(rp)).toBe("\uFFFD\uFFFD.txt");
  });
});

describe("byte-level path joins", () => {
  it("joins children onto the root without doubling the slash", () => {
    expect(rpJoin(ROOT, rpFromUtf8("etc"))).toEqual({ utf8: "/etc" });
    expect(rpBytes(rpJoin(ROOT, rpFromUtf8("etc")))).toEqual(utf8ToBytes("/etc"));
  });

  it("joins nested paths on raw bytes", () => {
    const p = rpJoin(rpFromUtf8("/etc"), rpFromUtf8("nginx"));
    expect(p).toEqual({ utf8: "/etc/nginx" });
    const deep = rpJoin(p, rpFromUtf8("sites-enabled"));
    expect(deep).toEqual({ utf8: "/etc/nginx/sites-enabled" });
  });

  it("joins a non-UTF-8 child onto a UTF-8 parent without decoding", () => {
    const parent = rpFromUtf8("/var/www");
    const child = rpFromBytes(new Uint8Array([0xff, 0xfe]));
    const joined = rpJoin(parent, child);
    expect(joined.base64).toBeDefined();
    expect(Array.from(rpBytes(joined))).toEqual([...utf8ToBytes("/var/www/"), 0xff, 0xfe]);
    // The identity key is stable and unambiguous.
    expect(rpSerialize(joined)).toContain("b64:");
  });
});

describe("dirname/basename/split", () => {
  it("splits a UTF-8 path into root + components", () => {
    expect(rpSplit(rpFromUtf8("/etc/nginx"))).toEqual([ROOT, { utf8: "etc" }, { utf8: "nginx" }]);
    expect(rpSplit(ROOT)).toEqual([ROOT]);
  });

  it("builds cumulative breadcrumb targets without joining root twice", () => {
    expect(rpBreadcrumbPaths(rpFromUtf8("/etc/nginx"))).toEqual([
      ROOT,
      { utf8: "/etc" },
      { utf8: "/etc/nginx" },
    ]);
  });

  it("keeps non-UTF-8 components raw through split", () => {
    const joined = rpJoin(rpJoin(ROOT, rpFromUtf8("srv")), rpFromBytes(new Uint8Array([0xff, 0xfe])));
    const parts = rpSplit(joined);
    expect(parts).toHaveLength(3);
    expect(parts[1]).toEqual({ utf8: "srv" });
    expect(parts[2].base64).toBeDefined();
    expect(rpDisplay(parts[2])).toBe("\uFFFD\uFFFD");
  });

  it("computes parent and basename on raw bytes", () => {
    expect(rpParent(rpFromUtf8("/etc/nginx/conf.d"))).toEqual({ utf8: "/etc/nginx" });
    expect(rpParent(rpFromUtf8("/top"))).toEqual(ROOT);
    expect(rpBasename(rpFromUtf8("/etc/nginx/conf.d"))).toEqual({ utf8: "conf.d" });
    expect(rpIsRoot(ROOT)).toBe(true);
    expect(rpIsRoot(rpFromUtf8("/etc"))).toBe(false);
  });

  it("derives the zip-destination stem from the raw basename", () => {
    expect(rpStem(rpFromUtf8("/var/www/release.zip"))).toEqual({ utf8: "release" });
    expect(rpStem(rpFromUtf8("/var/www/.env"))).toEqual({ utf8: ".env" });
  });
});

describe("leaf names", () => {
  it("rejects paths and traversal while allowing ordinary POSIX names", () => {
    expect(validateLeafName("backups")).toBeNull();
    expect(validateLeafName("release 2026")).toBeNull();
    expect(validateLeafName("..")).toContain("other than");
    expect(validateLeafName("nested/name")).toContain("slash");
    expect(validateLeafName("bad\nname")).toContain("control");
  });
});

describe("entry helpers", () => {
  function entry(name: RemotePath, display: string): SftpEntry {
    return {
      name,
      display,
      kind: "file",
      size: 1,
      mtime: 0,
      mode: "rw-r--r--",
      uid: 0,
      gid: 0,
      link_target: null,
    };
  }

  it("decodes raw name bytes from the base64 form, never display", () => {
    const raw = new Uint8Array([0xff, 0xfe]);
    const e = entry({ base64: bytesToBase64(raw) }, "\uFFFD\uFFFD");
    expect(Array.from(entryNameBytes(e))).toEqual([0xff, 0xfe]);
    expect(entryKey(e)).toBe(`b64:${bytesToBase64(raw)}`);
  });

  it("hides only entries whose raw first byte is a dot", () => {
    expect(entryHidden(entry({ utf8: ".env" }, ".env"))).toBe(true);
    expect(entryHidden(entry({ utf8: "app.env" }, "app.env"))).toBe(false);
    expect(entryHidden(entry({ base64: bytesToBase64(new Uint8Array([0x2e, 0xff])) }, "?\uFFFD"))).toBe(true);
  });

  it("recognizes dot entries", () => {
    expect(entryIsDot(entry({ utf8: "." }, "."))).toBe(true);
    expect(entryIsDot(entry({ utf8: ".." }, ".."))).toBe(true);
    expect(entryIsDot(entry({ utf8: "app" }, "app"))).toBe(false);
  });
});
