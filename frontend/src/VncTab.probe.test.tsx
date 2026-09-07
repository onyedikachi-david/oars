import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { VncTab } from "./VncTab";
import { mockBridge } from "./test/mock-bridge";
vi.mock("@novnc/novnc", () => ({ default: class extends EventTarget { disconnect() {} } }));
const installed = { ok: true, x11vnc: true, tigervnc: false, desktop_installed: true, desktop_running: false, window_manager_running: false, desktop_name: "XFCE", listening: [] };
beforeEach(() => { mockBridge.reset(); mockBridge.install(); mockBridge.setHandler("oars.vnc.probe", () => installed); });
it("keeps a disabled checking button visible during a manual probe", async () => {
  render(<VncTab serverId="probe-fixture" />);
  const button = await screen.findByRole("button", { name: "Re-probe" });
  let resolve!: (value: typeof installed) => void;
  mockBridge.setHandler("oars.vnc.probe", () => new Promise(r => { resolve = r; }));
  fireEvent.click(button);
  expect((screen.getByRole("button", { name: "Checking…" }) as HTMLButtonElement).disabled).toBe(true);
  await act(async () => resolve(installed));
  expect(await screen.findByRole("button", { name: "Re-probe" })).toBeTruthy();
});
it("offers to restart installed VNC when the desktop is running but its listener is stopped", async () => {
  mockBridge.setHandler("oars.vnc.probe", () => ({ ...installed, desktop_running: true, window_manager_running: true }));
  render(<VncTab serverId="probe-fixture" />);
  expect(await screen.findByRole("button", { name: "Start VNC server" })).toBeTruthy();
});
it("discards an earlier display's late probe response", async () => {
  let resolve!: (value: typeof installed) => void;
  mockBridge.setHandler("oars.vnc.probe", payload => payload.display === 0 ? new Promise(r => { resolve = r; }) : { ...installed, desktop_running: true });
  render(<VncTab serverId="race-fixture" />);
  fireEvent.click(screen.getByRole("button", { name: ":1" }));
  await screen.findByText(/display :1 running/);
  await act(async () => resolve(installed));
  expect(screen.getByText(/display :1 running/)).toBeTruthy();
});
it("stops setup when its fresh probe fails", async () => {
  render(<VncTab serverId="probe-fixture" />);
  const start = await screen.findByRole("button", { name: "Start desktop" });
  mockBridge.setHandler("oars.vnc.probe", () => { throw new Error("Connection lost"); });
  const setup = mockBridge.spyOn("oars.vnc.setup");
  fireEvent.click(start);
  await screen.findByText(/Could not confirm the remote desktop state/);
  expect(setup).not.toHaveBeenCalled();
  expect(screen.queryByText(/VNC server: not found/)).toBeNull();
});

it("does not open an old setup plan after the selected display changes", async () => {
  let resolve!: (value: unknown) => void;
  mockBridge.setHandler("oars.vnc.setup", () => new Promise(r => { resolve = r; }));
  const setup = mockBridge.spyOn("oars.vnc.setup");
  render(<VncTab serverId="setup-race" />);
  fireEvent.click(await screen.findByRole("button", { name: "Start desktop" }));
  await waitFor(() => expect(setup).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: ":1" }));
  await screen.findByText(/display :1 stopped/);
  await act(async () => resolve({ ok: true, action: "configure", plan: "", desktop_action: "start", desktop_name: "XFCE" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect((screen.getByRole("button", { name: "Start desktop" }) as HTMLButtonElement).disabled).toBe(false);
});
it("does not call an unchecked listener stopped", async () => {
  mockBridge.setHandler("oars.vnc.probe", () => ({ ...installed, desktop_running: true, listeners_checked: false }));
  render(<VncTab serverId="probe-fixture" />);
  await screen.findByText(/listener status unavailable/);
  expect(screen.queryByRole("button", { name: "Start VNC server" })).toBeNull();
});
it("reuses a saved password for reviewed startup without reinstalling", async () => {
  mockBridge.setHandler("native-sdk.credentials.get", () => "fixture-password");
  mockBridge.setHandler("oars.vnc.setup", () => ({ ok: true, action: "configure", executed: false, plan: "", hint: "Start the existing desktop", desktop_action: "start", desktop_name: "XFCE" }));
  const setup = mockBridge.spyOn("oars.vnc.setup");
  render(<VncTab serverId="probe-fixture" />);
  fireEvent.click(await screen.findByRole("button", { name: "Start desktop" }));
  await screen.findByRole("dialog");
  expect((screen.getByTestId("vnc-setup-password") as HTMLInputElement).value).toBe("fixture-password");
  expect(setup.mock.calls.every(([payload]) => payload.dry_run === true)).toBe(true);
});
it("does not offer desktop startup over an inaccessible existing X display", async () => {
  mockBridge.setHandler("oars.vnc.probe", () => ({ ...installed, display_present: true, display_accessible: false, display_managed: false }));
  render(<VncTab serverId="auth-fixture" />);
  await screen.findByText(/authorization required/);
  expect(screen.queryByRole("button", { name: "Start desktop" })).toBeNull();
  expect(screen.getByRole("button", { name: "Check display :1" })).toBeTruthy();
});
