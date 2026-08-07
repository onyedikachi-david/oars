import { describe, expect, it, vi } from "vitest";
import { api, vault } from "./bridge";
import {
  closedTunnelReason,
  desktopProbeLabel,
  legacyVncAuthWarning,
  validateSetupPasswords,
  validateVncPort,
} from "./vnc-state";

describe("VNC input contracts", () => {
  it("validates the supported VNC port range", () => {
    expect(validateVncPort("5900")).toEqual({ ok: true, value: 5900 });
    expect(validateVncPort("5999")).toEqual({ ok: true, value: 5999 });
    expect(validateVncPort("5899").ok).toBe(false);
    expect(validateVncPort("59x0").ok).toBe(false);
  });

  it("requires matching setup passwords", () => {
    expect(validateSetupPasswords("", "")).toBe("Enter a VNC password");
    expect(validateSetupPasswords("one", "two")).toBe("Passwords do not match");
    expect(validateSetupPasswords("same", "same")).toBeNull();
  });

  it("only warns for legacy password-only authentication", () => {
    expect(legacyVncAuthWarning(["password"])).toBe(true);
    expect(legacyVncAuthWarning(["username", "password", "target"])).toBe(false);
  });

  it("turns a closed poll into a terminal reason", () => {
    expect(closedTunnelReason({ state: "connected", error: "" })).toBeNull();
    expect(closedTunnelReason({ state: "closed", error: "channel open failed" })).toBe("channel open failed");
    expect(closedTunnelReason({ state: "closed", error: "" })).toBe("The VNC tunnel closed");
  });

  it("separates installed desktop state from the selected display", () => {
    expect(desktopProbeLabel({ desktop_installed: true, window_manager_running: true, desktop_surface_running: true, desktop_panel_running: true, desktop_running: true, desktop_name: "XFCE" }, 1)).toBe("XFCE installed · display :1 running");
    expect(desktopProbeLabel({ desktop_installed: true, window_manager_running: false, desktop_surface_running: false, desktop_panel_running: false, desktop_running: false, desktop_name: "XFCE" }, 0)).toBe("XFCE installed · display :0 stopped");
    expect(desktopProbeLabel({ desktop_installed: true, window_manager_running: true, desktop_surface_running: false, desktop_panel_running: false, desktop_running: false, desktop_name: "XFCE" }, 0)).toBe("XFCE installed · display :0 incomplete (missing desktop and panel)");
    expect(desktopProbeLabel({ desktop_installed: false, window_manager_running: false, desktop_surface_running: false, desktop_panel_running: false, desktop_running: false, desktop_name: "" }, 2)).toBe("not installed · display :2 stopped");
  });
});

describe("VNC bridge and Keychain contracts", () => {
  it("sends the setup password separately from the command preview", async () => {
    const invoke = vi.fn(async () => ({ ok: true, action: "configure", plan: "", hint: "safe", executed: true }));
    Object.defineProperty(globalThis, "window", { configurable: true, value: { zero: { invoke } } });

    await api.vnc.setup("server-1", { display: 1, dry_run: true });
    await api.vnc.setup("server-1", { display: 1, dry_run: false, password: "vnc-secret", installDesktop: true });

    expect(invoke).toHaveBeenNthCalledWith(1, "oars.vnc.setup", {
      server_id: "server-1",
      display: 1,
      dry_run: true,
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "oars.vnc.setup", {
      server_id: "server-1",
      display: 1,
      dry_run: false,
      password: "vnc-secret",
      install_desktop: true,
    });
  });

  it("probes desktop state on the selected display", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    Object.defineProperty(globalThis, "window", { configurable: true, value: { zero: { invoke } } });

    await api.vnc.probe("server-1", 2);

    expect(invoke).toHaveBeenCalledWith("oars.vnc.probe", { server_id: "server-1", display: 2 });
  });

  it("replaces and removes the cached Keychain password", async () => {
    const stored = new Map<string, string>();
    const invoke = vi.fn(async (command: string, payload: { account: string; secret?: string }) => {
      if (command.endsWith(".set")) stored.set(payload.account, payload.secret ?? "");
      if (command.endsWith(".delete")) stored.delete(payload.account);
      if (command.endsWith(".get")) return stored.get(payload.account) ?? null;
      return { ok: true };
    });
    Object.defineProperty(globalThis, "window", { configurable: true, value: { zero: { invoke } } });
    const account = "vnc:test-replace";

    await vault.set(account, "first");
    await vault.set(account, "second");
    expect(await vault.get(account)).toBe("second");
    await vault.delete(account);
    expect(await vault.get(account)).toBeNull();
  });
});
