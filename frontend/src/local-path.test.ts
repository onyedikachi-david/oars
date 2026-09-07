import { describe, expect, it } from "vitest";
import { localJoin, localParent } from "./local-path";

describe("local paths", () => {
  it("keeps POSIX and drive roots stable", () => {
    expect(localParent("/Users/oars/Documents")).toBe("/Users/oars");
    expect(localParent("/")).toBe("/");
    expect(localParent("/file.txt")).toBe("/");
    expect(localParent("C:\\Users\\oars")).toBe("C:\\Users");
    expect(localParent("C:\\Users")).toBe("C:\\");
    expect(localParent("C:\\")).toBe("C:\\");
  });

  it("handles bare filenames and trailing slashes", () => {
    expect(localParent("bare_filename.txt")).toBe("bare_filename.txt");
    expect(localParent("/home/user/docs///")).toBe("/home/user");
  });

  it("joins with the native separator and neutralizes nested names", () => {
    expect(localJoin("/Users/oars", "report.txt")).toBe("/Users/oars/report.txt");
    expect(localJoin("C:\\Users\\oars", "report.txt")).toBe("C:\\Users\\oars\\report.txt");
    expect(localJoin("/tmp", "nested/name.txt")).toBe("/tmp/nested_name.txt");
    expect(localJoin("/tmp", "nested\\name.txt")).toBe("/tmp/nested_name.txt");
    expect(localJoin("C:\\tmp", "dir/file.txt")).toBe("C:\\tmp\\dir_file.txt");
    expect(localJoin("/tmp/", "file.txt")).toBe("/tmp/file.txt");
  });
});
