import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DeployTab } from "./DeployTab";
import { mockBridge } from "../../test/mock-bridge";
import type { DeployPreflight } from "../../types";

describe("DeployTab Integration Suite", () => {
  const defaultPreflight: DeployPreflight = {
    id: 10,
    app_id: "app-1",
    server_id: "srv-prod",
    created_at_ms: Date.now(),
    expires_at_ms: Date.now() + 600000,
    app_revision: 1,
    target_fingerprint: 12345,
    status: "ready",
    facts: {
      os: "Ubuntu 22.04 LTS",
      arch: "x86_64",
      libc: "glibc",
      user: "ubuntu",
      home: "/home/ubuntu",
      privilege: "root",
      repository_commit: "abc123456789",
      lockfiles: "package-lock.json",
      git_host_fingerprints: "SHA256:github-key",
      ports: "3000/tcp open",
    },
    blockers: [],
    warnings: [],
    approvals: [],
    configs: { env: "NODE_ENV=production", pm2: "", nginx: "" },
    steps: [
      {
        id: "s1",
        label: "Pull repository",
        mutation: "Git clone",
        command: "git pull",
        skipped: false,
        files: [],
        guards: [],
        rollback: "",
      },
    ],
    commit: "abc123456789",
  };

  beforeEach(() => {
    mockBridge.reset();
    mockBridge.install();
  });

  it("loads applications once when parent callbacks change identity", async () => {
    const listSpy = mockBridge.spyOn("oars.deploy.apps.list");
    const { rerender } = render(
      <DeployTab serverId="srv-prod" onAppsLoaded={() => {}} onClearPendingApp={() => {}} />,
    );

    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);
    expect(listSpy).toHaveBeenCalledTimes(1);

    rerender(
      <DeployTab serverId="srv-prod" onAppsLoaded={() => {}} onClearPendingApp={() => {}} />,
    );

    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(listSpy).toHaveBeenCalledTimes(1);
  });

  it("Scenario 1: Preflight gathering-to-ready polling and server facts inspection", async () => {
    let pollCount = 0;
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: { ...defaultPreflight, status: "gathering" },
    }));

    mockBridge.setHandler("oars.deploy.preflightPoll", () => {
      pollCount++;
      if (pollCount === 1) {
        return { ok: true, preflight: { ...defaultPreflight, status: "ready" } };
      }
      return { ok: true, preflight: { ...defaultPreflight, status: "ready" } };
    });

    render(<DeployTab serverId="srv-prod" />);

    // App rail renders and selects default app
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    const preflightBtn = screen.getByRole("button", { name: /Run preflight/i });
    fireEvent.click(preflightBtn);

    // Transitions through gathering to ready
    expect(await screen.findByText(/Ready for approval/i, {}, { timeout: 8000 })).toBeTruthy();
    expect(screen.getByText(/Ubuntu 22\.04 LTS/)).toBeTruthy();
    expect(screen.getByText(/x86_64/)).toBeTruthy();
    expect(screen.getByText(/Pull repository/)).toBeTruthy();
  });

  it("Scenario 2: Preflight blockers halting deployment", async () => {
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: {
        ...defaultPreflight,
        status: "blocked",
        blockers: [{ id: "b1", message: "Port 3000 already in use by process 999" }],
      },
    }));

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    const preflightBtn = screen.getByRole("button", { name: /Run preflight/i });
    fireEvent.click(preflightBtn);

    // Blocker alert is rendered
    expect(await screen.findByText(/Deployment blocked/i)).toBeTruthy();
    expect(screen.getByText(/Port 3000 already in use by process 999/)).toBeTruthy();

    // Deploy button is disabled
    const deployBtn = screen.getByRole("button", { name: /Deploy reviewed plan/i });
    expect(deployBtn.hasAttribute("disabled")).toBe(true);
  });

  it("Scenario 3: Unapproved mutation prevention", async () => {
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: {
        ...defaultPreflight,
        status: "ready",
        approvals: [{ id: "appr-nginx", label: "Install system packages", detail: "nginx, certbot" }],
      },
    }));

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    expect(await screen.findByText(/Install system packages/i)).toBeTruthy();

    // Deploy button remains disabled when approval is not checked
    const deployBtn = screen.getByRole("button", { name: /Deploy reviewed plan/i });
    expect(deployBtn.hasAttribute("disabled")).toBe(true);

    // Check approval
    const checkbox = screen.getByRole("checkbox") as HTMLInputElement;
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(true);
  });

  it("Scenario 4: Missing secret validation error banner", async () => {
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: defaultPreflight,
    }));

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    expect(await screen.findByText(/Ready for approval/i)).toBeTruthy();

    // The app has a secret env var APP_SECRET that is currently empty
    const deployBtn = screen.getByRole("button", { name: /Deploy reviewed plan/i });
    fireEvent.click(deployBtn);

    // Error alert banner is shown
    expect(await screen.findByText(/Enter or store a value for APP_SECRET/i)).toBeTruthy();
  });

  it("Scenario 5: Transient secret capture and deployment trigger", async () => {
    const runSpy = mockBridge.spyOn("oars.deploy.run");
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: defaultPreflight,
    }));

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    expect(await screen.findByText(/Ready for approval/i)).toBeTruthy();

    // Enter secret via label
    const secretInput = screen.getByLabelText("APP_SECRET");
    fireEvent.change(secretInput, { target: { value: "super-secret-token-99" } });

    // Click Deploy reviewed plan
    const deployBtn = screen.getByRole("button", { name: /Deploy reviewed plan/i });
    fireEvent.click(deployBtn);

    await waitFor(() => {
      expect(runSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          preflight_id: defaultPreflight.id,
          secret_values: [{ name: "APP_SECRET", value: "super-secret-token-99" }],
        })
      );
    });
  });

  it("Scenario 6: Execution output streaming and gap recovery", async () => {
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: defaultPreflight,
    }));

    mockBridge.setHandler("oars.deploy.run", () => {
      mockBridge.state.deployRuns.set(101, {
        status: "running",
        done: false,
        steps: [
          { channel: 1, cursor: 25, output: "Streaming step 1 output...\n", gap: true, state: "running" },
        ],
      });
      return { ok: true, run_id: 101 };
    });

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    await screen.findByText(/Ready for approval/i, {}, { timeout: 8000 });

    // Provide secret and run
    const secretInput = screen.getByLabelText("APP_SECRET");
    fireEvent.change(secretInput, { target: { value: "token" } });
    fireEvent.click(screen.getByRole("button", { name: /Deploy reviewed plan/i }));

    // DeployOutputPane is displayed with run # and output
    expect(await screen.findByText(/Run #101/i)).toBeTruthy();
    expect(await screen.findByText(/Streaming step 1 output/i)).toBeTruthy();
    expect(await screen.findByText(/Earlier output was dropped/i)).toBeTruthy();
  });

  it("Scenario 7: Deployment completion and history reload", async () => {
    const historySpy = mockBridge.spyOn("oars.deploy.history");
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: defaultPreflight,
    }));

    mockBridge.setHandler("oars.deploy.run", () => {
      mockBridge.state.deployRuns.set(102, {
        status: "done",
        done: true,
        steps: [
          { channel: 1, cursor: 20, output: "Finished deployment\n", state: "done" },
        ],
      });
      return { ok: true, run_id: 102 };
    });

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    await screen.findByText(/Ready for approval/i, {}, { timeout: 8000 });

    const secretInput = screen.getByLabelText("APP_SECRET");
    fireEvent.change(secretInput, { target: { value: "token" } });
    fireEvent.click(screen.getByRole("button", { name: /Deploy reviewed plan/i }));

    expect(await screen.findByText(/Run #102/i)).toBeTruthy();

    // Output pane indicates done and triggers history reload
    await waitFor(() => {
      expect(historySpy).toHaveBeenCalled();
    });
  });

  it("Scenario 8: Deployment cancellation", async () => {
    const cancelSpy = mockBridge.spyOn("oars.deploy.cancel");
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: defaultPreflight,
    }));

    mockBridge.setHandler("oars.deploy.run", () => {
      mockBridge.state.deployRuns.set(103, {
        status: "running",
        done: false,
        steps: [
          { channel: 1, cursor: 10, output: "Long running build...\n", state: "running" },
        ],
      });
      return { ok: true, run_id: 103 };
    });

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    await screen.findByText(/Ready for approval/i, {}, { timeout: 8000 });

    const secretInput = screen.getByLabelText("APP_SECRET");
    fireEvent.change(secretInput, { target: { value: "token" } });
    fireEvent.click(screen.getByRole("button", { name: /Deploy reviewed plan/i }));

    expect(await screen.findByText(/Run #103/i)).toBeTruthy();

    const cancelBtn = await screen.findByRole("button", { name: /Request cancel/i });
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(cancelSpy).toHaveBeenCalledWith(
        expect.objectContaining({ run_id: 103 })
      );
    });
  });

  it("Scenario 9: SSH Deploy key generation and Git host trust", async () => {
    const trustSpy = mockBridge.spyOn("oars.deploy.hostTrust");
    mockBridge.setHandler("oars.deploy.preflight", () => ({
      ok: true,
      preflight: {
        ...defaultPreflight,
        blockers: [{ id: "missing_deploy_key", message: "SSH key required for private repo" }],
        approvals: [{ id: "git-host-key", label: "Trust Git host key", detail: "github.com" }],
      },
    }));

    render(<DeployTab serverId="srv-prod" />);
    expect((await screen.findAllByText("Web API")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /Run preflight/i }));
    expect(await screen.findByText(/SSH key required for private repo/i)).toBeTruthy();

    // Click "Create key"
    const generateBtn = screen.getByRole("button", { name: /Create key/i });
    fireEvent.click(generateBtn);

    // Public key is displayed
    expect(await screen.findByText(/ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenKey123/i)).toBeTruthy();

    // Check git-host-key approval
    const trustCheckbox = screen.getByRole("checkbox") as HTMLInputElement;
    fireEvent.click(trustCheckbox);

    // Click "Trust host and check again" button
    const trustBtn = screen.getByRole("button", { name: /Trust host and check again/i });
    fireEvent.click(trustBtn);

    // Preflight triggers host trust
    await waitFor(() => {
      expect(trustSpy).toHaveBeenCalled();
    });
  });
});
