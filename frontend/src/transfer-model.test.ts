import { describe, expect, it } from "vitest";
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
} from "./transfer-model";
import { rpFromUtf8 } from "./sftp-path";

function fakeFile(name: string, size: number): File {
  return new File([new Uint8Array(size)], name, { type: "application/octet-stream" });
}

describe("transfer ids and chunking", () => {
  it("generates nonzero transfer ids", () => {
    for (let i = 0; i < 50; i++) expect(nextTransferId()).toBeGreaterThan(0);
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

  it("reports directory-upload support from File.prototype only", () => {
    // Node's File has no webkitRelativePath, so the honest answer is
    // false; the packaged WebView answers true when it provides it.
    expect(directoryUploadSupported()).toBe(false);
    expect(fileRelativePath(fakeFile("a.txt", 1))).toBeUndefined();
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
