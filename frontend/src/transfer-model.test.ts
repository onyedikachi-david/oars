import { describe, expect, it, vi } from "vitest";
import {
  MAX_CONCURRENT_UPLOADS,
  UPLOAD_CHUNK_BYTES,
  directoryUploadSupported,
  emptyUploadModel,
  fileRelativePath,
  nextUploadOffset,
  nextTransferId,
  uploadDirectoryPaths,
  uploadActive,
  uploadJobFor,
  uploadReducer,
  validateUploadRelativePath,
} from "./transfer-model";
import { rpFromUtf8 } from "./sftp-path";

function fakeFile(name: string, size: number, relativePath?: string): File {
  const f = new File([new Uint8Array(size)], name, { type: "application/octet-stream" });
  if (relativePath !== undefined) {
    Object.defineProperty(f, "webkitRelativePath", { value: relativePath });
  }
  return f;
}

describe("transfer ids and chunking", () => {
  it("generates nonzero transfer ids", () => {
    for (let i = 0; i < 50; i++) expect(nextTransferId()).toBeGreaterThan(0);
  });

  it("falls back to 1 when crypto.getRandomValues produces 0", () => {
    const original = crypto.getRandomValues;
    try {
      crypto.getRandomValues = ((arr: Uint32Array) => {
        arr[0] = 0;
        return arr;
      }) as any;
      expect(nextTransferId()).toBe(1);
    } finally {
      crypto.getRandomValues = original;
    }
  });

  it("uploads in 64 KiB chunks with concurrency capped at three", () => {
    expect(UPLOAD_CHUNK_BYTES).toBe(64 * 1024);
    expect(MAX_CONCURRENT_UPLOADS).toBe(3);
  });

  it("uses the worker's cumulative write offset", () => {
    expect(nextUploadOffset(0, 65_536, 65_536, 131_072)).toBe(65_536);
    expect(nextUploadOffset(65_536, 65_536, 131_072, 131_072)).toBe(131_072);
    expect(() => nextUploadOffset(65_536, 65_536, 65_536, 131_072)).toThrow("short write");
  });

  it("validates write offset safety against non-integers and overflows", () => {
    expect(() => nextUploadOffset(0, 100, NaN, 200)).toThrow("short write");
    expect(() => nextUploadOffset(0, 100, Infinity, 200)).toThrow("short write");
    expect(() => nextUploadOffset(0, 100, 100.5, 200)).toThrow("short write");
    expect(() => nextUploadOffset(0, 100, 250, 200)).toThrow("short write");
  });
});

describe("relative path validation", () => {
  it("rejects leading slashes and backslashes", () => {
    expect(() => validateUploadRelativePath("/var/log")).toThrow("stay inside the selected folder");
    expect(() => validateUploadRelativePath("folder\\file.txt")).toThrow("stay inside the selected folder");
  });

  it("rejects empty parts, double slashes, dot components, and control characters", () => {
    expect(() => validateUploadRelativePath("")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("a//b")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("./file.txt")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("../file.txt")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("a/\0/b")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("a/\x1f/b")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("a/\x7f/b")).toThrow("invalid folder name");
  });

  it("accepts valid relative path structures", () => {
    expect(validateUploadRelativePath("app/src/index.ts")).toEqual(["app", "src", "index.ts"]);
    expect(validateUploadRelativePath("single_file.txt")).toEqual(["single_file.txt"]);
  });
});

describe("upload jobs", () => {
  it("builds a destination from raw path bytes, never display text", () => {
    const job = uploadJobFor("prod", rpFromUtf8("/var/www"), fakeFile("release.zip", 10));
    expect(job.path).toEqual({ utf8: "/var/www/release.zip" });
    expect(job.display).toBe("/var/www/release.zip");
    expect(job.total).toBe(10);
    expect(job.status).toBe("queued");
  });

  it("mirrors local folder structure when relative paths exist", () => {
    const job = uploadJobFor("prod", rpFromUtf8("/srv"), fakeFile("x.js", 1), "app/src/x.js");
    expect(job.path).toEqual({ utf8: "/srv/app/src/x.js" });
  });

  it("plans unique parent directories before directory uploads", () => {
    expect(uploadDirectoryPaths(rpFromUtf8("/srv"), ["app/src/x.js", "app/public/logo.svg"]))
      .toEqual([
        { utf8: "/srv/app" },
        { utf8: "/srv/app/src" },
        { utf8: "/srv/app/public" },
      ]);
    expect(() => uploadDirectoryPaths(rpFromUtf8("/srv"), ["../escape.txt"])).toThrow("invalid folder name");
  });

  it("handles undefined, empty, and duplicate paths in uploadDirectoryPaths", () => {
    const paths = uploadDirectoryPaths(rpFromUtf8("/srv"), [undefined, "", "nested/file.txt", "nested/another.txt", undefined]);
    expect(paths).toEqual([{ utf8: "/srv/nested" }]);
  });

  it("reports directory-upload support from File.prototype only", () => {
    expect(directoryUploadSupported()).toBe(false);
    expect(fileRelativePath(fakeFile("a.txt", 1))).toBeUndefined();
    expect(fileRelativePath(fakeFile("b.txt", 1, ""))).toBeUndefined();
    expect(fileRelativePath(fakeFile("c.txt", 1, "dir/c.txt"))).toBe("dir/c.txt");
  });
});

describe("upload reducer", () => {
  it("tracks progress, completion, and failure honestly", () => {
    let model = emptyUploadModel();
    const job = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("f.bin", 100));
    model = uploadReducer(model, { type: "register", job });
    expect(model.active).toBe(0);
    model = uploadReducer(model, { type: "start", transferId: job.transferId });
    expect(model.active).toBe(1);
    expect(model.jobs[0].status).toBe("running");
    model = uploadReducer(model, { type: "progress", transferId: job.transferId, bytesSent: 40 });
    expect(model.jobs[0].bytesSent).toBe(40);
    model = uploadReducer(model, { type: "done", transferId: job.transferId });
    expect(model.jobs[0].status).toBe("done");
    expect(model.jobs[0].bytesSent).toBe(100);
    expect(model.active).toBe(0);
    expect(uploadActive(model.jobs[0])).toBe(false);
  });

  it("ignores actions for unknown transfer ids", () => {
    let model = emptyUploadModel();
    const job = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("f.bin", 100));
    model = uploadReducer(model, { type: "register", job });
    const untouched = uploadReducer(model, { type: "start", transferId: 99999 });
    expect(untouched).toBe(model);
    const untouchedProgress = uploadReducer(model, { type: "progress", transferId: 99999, bytesSent: 10 });
    expect(untouchedProgress.jobs[0].bytesSent).toBe(0);
  });

  it("handles non-running job transitions to done, failed, or canceled without decrementing active below 0", () => {
    let model = emptyUploadModel();
    const job1 = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("1.bin", 100));
    const job2 = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("2.bin", 100));
    const job3 = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("3.bin", 100));
    model = uploadReducer(model, { type: "register", job: job1 });
    model = uploadReducer(model, { type: "register", job: job2 });
    model = uploadReducer(model, { type: "register", job: job3 });

    // Directly complete queued job1
    model = uploadReducer(model, { type: "done", transferId: job1.transferId });
    expect(model.jobs[0].status).toBe("done");
    expect(model.active).toBe(0);

    // Directly fail queued job2
    model = uploadReducer(model, { type: "failed", transferId: job2.transferId, error: "Direct fail" });
    expect(model.jobs[1].status).toBe("failed");
    expect(model.jobs[1].error).toBe("Direct fail");
    expect(model.active).toBe(0);

    // Directly cancel queued job3
    model = uploadReducer(model, { type: "canceled", transferId: job3.transferId });
    expect(model.jobs[2].status).toBe("canceled");
    expect(model.active).toBe(0);
  });

  it("marks a failed upload without faking success", () => {
    let model = emptyUploadModel();
    const job = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("f.bin", 100));
    model = uploadReducer(model, { type: "register", job });
    model = uploadReducer(model, { type: "start", transferId: job.transferId });
    model = uploadReducer(model, { type: "failed", transferId: job.transferId, error: "permission denied" });
    expect(model.jobs[0].status).toBe("failed");
    expect(model.jobs[0].error).toBe("permission denied");
    expect(model.active).toBe(0);
  });

  it("stops cleanly on cancel", () => {
    let model = emptyUploadModel();
    const job = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("f.bin", 100));
    model = uploadReducer(model, { type: "register", job });
    model = uploadReducer(model, { type: "start", transferId: job.transferId });
    model = uploadReducer(model, { type: "canceled", transferId: job.transferId });
    expect(model.jobs[0].status).toBe("canceled");
    expect(model.active).toBe(0);
  });

  it("does not decrement active twice when cancellation races the loop", () => {
    let model = emptyUploadModel();
    const job = uploadJobFor("prod", rpFromUtf8("/tmp"), fakeFile("f.bin", 100));
    model = uploadReducer(model, { type: "register", job });
    model = uploadReducer(model, { type: "start", transferId: job.transferId });
    model = uploadReducer(model, { type: "canceled", transferId: job.transferId });
    model = uploadReducer(model, { type: "canceled", transferId: job.transferId });
    expect(model.active).toBe(0);
  });

  it("never lets the active count go negative", () => {
    let model = emptyUploadModel();
    model = uploadReducer(model, { type: "done", transferId: 999 });
    expect(model.active).toBe(0);
  });
});
