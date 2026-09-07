import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LogsTab } from "./LogsTab";
import { mockBridge } from "./test/mock-bridge";
import type { Server } from "./types";

describe("LogsTab Integration Suite", () => {
  const mockServer: Server = {
    id: "srv-prod",
    name: "Production Server",
    host: "prod.internal",
    user: "ubuntu",
    port: 22,
    auth_method: "key",
    key_path: "~/.ssh/id_ed25519",
    key_has_passphrase: false,
    host_fingerprint: null,
    group: "",
    tags: [],
    via_server_id: null,
    created_at: 0,
    updated_at: 0,
  };

  beforeEach(() => {
    mockBridge.reset();
    mockBridge.install();

    mockBridge.state.logSources = [
      {
        path: "/var/log/nginx/access.log",
        name: "access.log",
        group: "web",
        size: 10240,
        mtime_epoch: 1700000000,
        mode: 0o644,
        readable: true,
        age_sec: 120,
      },
      {
        path: "/var/log/syslog",
        name: "syslog",
        group: "system",
        size: 51200,
        mtime_epoch: 1700000000,
        mode: 0o640,
        readable: true,
        age_sec: 120,
      },
    ];

    mockBridge.state.logLines.set("/var/log/nginx/access.log", [
      "127.0.0.1 - - [18/Aug/2026:12:00:01] GET / HTTP/1.1 200",
      "127.0.0.1 - - [18/Aug/2026:12:00:02] GET /api/health HTTP/1.1 200",
      "127.0.0.1 - - [18/Aug/2026:12:00:03] POST /api/login HTTP/1.1 401 ERROR",
      "127.0.0.1 - - [18/Aug/2026:12:00:04] POST /api/login HTTP/1.1 200",
    ]);

    mockBridge.state.logLines.set("/var/log/syslog", [
      "systemd[1]: Started Oars Agent Daemon",
      "kernel: [0.000000] Linux version 6.5.0",
    ]);
  });

  async function getRailSourceButton(name: RegExp) {
    const options = await screen.findAllByRole("option", { name });
    const btn = options.find((el) => el.tagName === "BUTTON");
    if (!btn) throw new Error(`Could not find button for source ${name}`);
    return btn;
  }

  it("Scenario 1: Log source discovery and categorized rail rendering", async () => {
    render(<LogsTab server={mockServer} />);

    // Renders log rail with groups
    expect(await screen.findByText("Log sources")).toBeTruthy();
    expect(screen.getByText("Web servers")).toBeTruthy();
    expect(screen.getByText("System")).toBeTruthy();

    expect(await getRailSourceButton(/access\.log/i)).toBeTruthy();
    expect(await getRailSourceButton(/syslog/i)).toBeTruthy();
  });

  it("Scenario 2: Static log reading and line count selector switching", async () => {
    const user = userEvent.setup();
    const readSpy = mockBridge.spyOn("oars.logs.read");
    render(<LogsTab server={mockServer} />);

    // Click access.log button in rail
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    // Initial read is for 200 lines
    await waitFor(() => {
      expect(readSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          path: "/var/log/nginx/access.log",
          lines: 200,
        })
      );
    });

    // The read request starts before the selector is enabled again.
    await waitFor(() => expect((screen.getByLabelText("Lines to load") as HTMLButtonElement).disabled).toBe(false));
    // Change line count to 500
    await user.click(screen.getByLabelText("Lines to load"));
    await user.click(screen.getByRole("option", { name: "500 lines" }));

    await waitFor(() => {
      expect(readSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          path: "/var/log/nginx/access.log",
          lines: 500,
        })
      );
    });
  });

  it("Scenario 3: Streaming follow mode initiation and live state polling", async () => {
    const followSpy = mockBridge.spyOn("oars.logs.follow");
    render(<LogsTab server={mockServer} />);

    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    // Click Follow button
    const followBtn = await screen.findByRole("button", { name: /Follow/i });
    fireEvent.click(followBtn);

    await waitFor(() => {
      expect(followSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          path: "/var/log/nginx/access.log",
        })
      );
    });

    // Badge indicates Live state
    expect(await screen.findByText("Live")).toBeTruthy();
  });

  it("Scenario 4: Absolute byte cursor tracking across follow polling deltas", async () => {
    mockBridge.setHandler("oars.logs.follow", () => ({ ok: true, channel: 42 }));

    let pollCount = 0;
    mockBridge.setHandler("oars.ssh.poll", (p: any) => {
      pollCount++;
      return {
        channels: [
          {
            id: 42,
            data: `Streaming line ${pollCount}\n`,
            cursor: 512 * pollCount,
            eof: false,
            dropped: 0,
          },
        ],
        closed: [],
      };
    });

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    const followBtn = await screen.findByRole("button", { name: /Follow/i });
    fireEvent.click(followBtn);

    expect(await screen.findByText("Live")).toBeTruthy();

    await waitFor(() => {
      expect(pollCount).toBeGreaterThanOrEqual(2);
    });
  });

  it("Scenario 5: Follow stream buffer bounding and dropped lines tracking", async () => {
    mockBridge.setHandler("oars.logs.follow", () => ({ ok: true, channel: 50 }));
    mockBridge.setHandler("oars.ssh.poll", () => {
      return {
        channels: [{ id: 50, data: "Stream chunk\n", cursor: 2000, eof: false, dropped: 4096 }],
        closed: [],
      };
    });

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    const followBtn = await screen.findByRole("button", { name: /Follow/i });
    fireEvent.click(followBtn);

    // Follow status shows Live and records dropped lines in state
    expect(await screen.findByText("Live")).toBeTruthy();
  });

  it("Scenario 6: Stream EOF and remote channel closing", async () => {
    const closeSpy = mockBridge.spyOn("oars.ssh.closeChannel");
    mockBridge.setHandler("oars.logs.follow", () => ({ ok: true, channel: 55 }));
    mockBridge.setHandler("oars.ssh.poll", () => {
      return {
        channels: [{ id: 55, data: "Final log line\n", cursor: 100, eof: true, dropped: 0 }],
        closed: [],
      };
    });

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    const followBtn = await screen.findByRole("button", { name: /Follow/i });
    // Follow is unavailable while the selected source is still loading.
    await waitFor(() => expect((followBtn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(followBtn);

    // EOF status badge and channel closure
    expect(await screen.findByText("Ended")).toBeTruthy();

    await waitFor(() => {
      expect(closeSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          channel: 55,
        })
      );
    });
  });

  it("Scenario 7: Clean channel teardown on log source switch", async () => {
    const closeSpy = mockBridge.spyOn("oars.ssh.closeChannel");
    mockBridge.state.sshChannels.set(77, {
      chunks: [{ text: "Initial stream line\n" }],
      cursor: 20,
      eof: false,
    });
    mockBridge.setHandler("oars.logs.follow", () => ({ ok: true, channel: 77 }));

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    // Wait for read to become ready and enable follow button
    await waitFor(() => {
      const followBtn = screen.getByRole("button", { name: /Follow/i });
      expect(followBtn.hasAttribute("disabled")).toBe(false);
    });

    // Start following access.log
    const followBtn = screen.getByRole("button", { name: /Follow/i });
    fireEvent.click(followBtn);
    expect(await screen.findByText(/Live|Starting/i)).toBeTruthy();

    // Switch to syslog
    const syslogBtn = await getRailSourceButton(/syslog/i);
    fireEvent.click(syslogBtn);

    // Verify channel 77 is closed immediately
    await waitFor(() => {
      expect(closeSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          channel: 77,
        })
      );
    });
  });

  it("Scenario 8: Real-time search query filtering and match counter", async () => {
    mockBridge.state.logLines.set("/var/log/nginx/access.log", [
      "GET / 200",
      "GET /assets/app.js 200",
      "POST /api/login 200",
      "POST /api/payment 500 ERROR",
    ]);

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    const searchInput = await screen.findByLabelText("Search loaded lines");
    fireEvent.change(searchInput, { target: { value: "ERROR" } });

    // Match pill displays "1 match"
    expect(await screen.findByText("1 match")).toBeTruthy();
  });

  it("Scenario 9: Identity-bound clear log with conflict detection and rescan", async () => {
    mockBridge.setHandler("oars.logs.clear", () => {
      return { ok: false, error: "file changed since preview" };
    });

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    // Click Clear button in toolbar
    const clearToolbarBtn = await screen.findByRole("button", { name: /Clear/i });
    fireEvent.click(clearToolbarBtn);

    // Modal appears
    expect(await screen.findByText(/Clear this log on the server\?/i)).toBeTruthy();

    // Confirm clear in modal
    const confirmBtn = screen.getByRole("button", { name: /^Clear log$/i });
    fireEvent.click(confirmBtn);

    // Conflict error banner appears
    expect(await screen.findByText(/file changed since preview/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Re-scan and review/i })).toBeTruthy();
  });

  it("Scenario 10: Binary log file detection and inspection safety", async () => {
    mockBridge.setHandler("oars.logs.read", () => {
      return {
        ok: true,
        path: "/var/log/nginx/access.log",
        lines: [],
        limited: false,
        binary: true,
      };
    });

    render(<LogsTab server={mockServer} />);
    const sourceBtn = await getRailSourceButton(/access\.log/i);
    fireEvent.click(sourceBtn);

    // Binary file warning rendered
    expect(await screen.findByText(/This file is not text/i)).toBeTruthy();

    // Follow button is disabled
    const followBtn = screen.getByRole("button", { name: /Follow/i });
    expect(followBtn.hasAttribute("disabled")).toBe(true);
  });
});
