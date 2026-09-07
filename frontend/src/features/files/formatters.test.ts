import { describe, expect, it } from "vitest";
import { BridgeError } from "../../bridge";
import { rpFromUtf8 } from "../../sftp-path";
import type { SftpEntry } from "../../types";
import {
  fmtBytes,
  fmtTime,
  errMessage,
  transferDisplay,
  kindLabel,
  isZipEntry,
  modeString,
} from "./formatters";

describe("features/files/formatters", () => {
  describe("fmtBytes", () => {
    it("handles non-finite and negative values", () => {
      expect(fmtBytes(-1)).toBe("—");
      expect(fmtBytes(NaN)).toBe("—");
      expect(fmtBytes(Infinity)).toBe("—");
      expect(fmtBytes(-Infinity)).toBe("—");
    });

    it("formats bytes, kilobytes, and megabytes", () => {
      expect(fmtBytes(0)).toBe("0 B");
      expect(fmtBytes(512)).toBe("512 B");
      expect(fmtBytes(1023)).toBe("1023 B");
      expect(fmtBytes(1024)).toBe("1.0 KB");
      expect(fmtBytes(1536)).toBe("1.5 KB");
      expect(fmtBytes(1048576)).toBe("1.0 MB");
      expect(fmtBytes(5242880)).toBe("5.0 MB");
    });
  });

  describe("fmtTime", () => {
    it("returns dash for zero or falsy epoch", () => {
      expect(fmtTime(0)).toBe("—");
      expect(fmtTime(NaN)).toBe("—");
    });

    it("formats valid epoch timestamp", () => {
      const formatted = fmtTime(1700000000);
      expect(formatted).toBeTruthy();
      expect(typeof formatted).toBe("string");
    });
  });

  describe("errMessage", () => {
    it("extracts message from BridgeError", () => {
      const err = new BridgeError("timeout", "Bridge operation timed out");
      expect(errMessage(err)).toBe("Bridge operation timed out");
    });

    it("extracts message from standard Error", () => {
      const err = new Error("Generic failure");
      expect(errMessage(err)).toBe("Generic failure");
    });

    it("converts primitives and objects to string", () => {
      expect(errMessage("raw text error")).toBe("raw text error");
      expect(errMessage(404)).toBe("404");
      expect(errMessage({ custom: "data" })).toBe("[object Object]");
    });
  });

  describe("transferDisplay", () => {
    it("decodes UTF-8 byte strings into unicode characters", () => {
      expect(transferDisplay("hello world")).toBe("hello world");
      expect(transferDisplay("\xC3\xA9")).toBe("é");
      expect(transferDisplay("\xC3\xBC")).toBe("ü");
    });

    it("falls back to replacement characters on malformed byte escape sequences", () => {
      const malformed = "\x80\x81";
      const result = transferDisplay(malformed);
      expect(result).toBeTruthy();
    });
  });

  describe("kindLabel", () => {
    it("maps all SftpEntry kinds to user-facing labels", () => {
      expect(kindLabel("file")).toBe("File");
      expect(kindLabel("dir")).toBe("Folder");
      expect(kindLabel("symlink")).toBe("Symlink");
      expect(kindLabel("other" as any)).toBe("Other");
    });
  });

  describe("isZipEntry", () => {
    it("identifies zip files regardless of casing", () => {
      const zipFile: SftpEntry = {
        kind: "file",
        name: rpFromUtf8("archive.zip"),
        display: "archive.zip",
        size: 100,
        mtime: 1700000000,
        mode: "-rw-r--r--",
        uid: 1000,
        gid: 1000,
        link_target: null,
      };
      expect(isZipEntry(zipFile)).toBe(true);

      const upperZip: SftpEntry = { ...zipFile, display: "BACKUP.ZIP" };
      expect(isZipEntry(upperZip)).toBe(true);
    });

    it("rejects non-zip files and directories named like zip files", () => {
      const dirEntry: SftpEntry = {
        kind: "dir",
        name: rpFromUtf8("archive.zip"),
        display: "archive.zip",
        size: 4096,
        mtime: 1700000000,
        mode: "drwxr-xr-x",
        uid: 1000,
        gid: 1000,
        link_target: null,
      };
      expect(isZipEntry(dirEntry)).toBe(false);

      const textEntry: SftpEntry = {
        kind: "file",
        name: rpFromUtf8("file.txt"),
        display: "file.txt",
        size: 200,
        mtime: 1700000000,
        mode: "-rw-r--r--",
        uid: 1000,
        gid: 1000,
        link_target: null,
      };
      expect(isZipEntry(textEntry)).toBe(false);
    });
  });

  describe("modeString", () => {
    it("formats standard file permissions", () => {
      expect(modeString(0o755)).toBe("rwxr-xr-x");
      expect(modeString(0o644)).toBe("rw-r--r--");
      expect(modeString(0o700)).toBe("rwx------");
      expect(modeString(0o000)).toBe("---------");
    });

    it("handles SUID bit with execute (s) and without execute (S)", () => {
      expect(modeString(0o4755)).toBe("rwsr-xr-x");
      expect(modeString(0o4655)).toBe("rwSr-xr-x");
      expect(modeString(0o4644)).toBe("rwSr--r--");
    });

    it("handles SGID bit with execute (s) and without execute (S)", () => {
      expect(modeString(0o2755)).toBe("rwxr-sr-x");
      expect(modeString(0o2655)).toBe("rw-r-sr-x");
      expect(modeString(0o2745)).toBe("rwxr-Sr-x");
      expect(modeString(0o2644)).toBe("rw-r-Sr--");
    });

    it("handles Sticky bit with execute (t) and without execute (T)", () => {
      expect(modeString(0o1777)).toBe("rwxrwxrwt");
      expect(modeString(0o1766)).toBe("rwxrw-rwT");
    });

    it("handles combination of special bits", () => {
      expect(modeString(0o7755)).toBe("rwsr-sr-t");
      expect(modeString(0o7644)).toBe("rwSr-Sr-T");
    });
  });
});
