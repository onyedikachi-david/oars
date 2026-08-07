import { describe, expect, it } from "vitest";
import { isCurrentLogRequest, nextLogCursor } from "./log-view-state";

describe("log request identity", () => {
  const token = { generation: 4, serverId: "prod", path: "/var/log/app.log" };

  it("accepts only the same generation, server, and source", () => {
    expect(isCurrentLogRequest(token, 4, "prod", "/var/log/app.log")).toBe(true);
    expect(isCurrentLogRequest(token, 5, "prod", "/var/log/app.log")).toBe(false);
    expect(isCurrentLogRequest(token, 4, "prod", "/var/log/other.log")).toBe(false);
    expect(isCurrentLogRequest(token, 4, "staging", "/var/log/app.log")).toBe(false);
  });
});

describe("follow cursors", () => {
  it("uses the backend absolute byte cursor for Unicode output", () => {
    const data = "ok 🚀";
    expect(data.length).toBe(5);
    expect(new TextEncoder().encode(data).length).toBe(7);
    expect(nextLogCursor(7)).toBe(7);
  });

  it("jumps across a dropped byte range", () => {
    expect(nextLogCursor(8192)).toBe(8192);
  });
});
