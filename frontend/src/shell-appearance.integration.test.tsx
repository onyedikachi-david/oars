import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mockBridge } from "./test/mock-bridge";
import { ShellIntegrationDialog } from "./components/ShellIntegrationDialog";
import { TerminalTab } from "./TerminalTab";
import { updateAppearance } from "./appearance";
import type { PollResult } from "./types";
const terminalState = vi.hoisted(() => ({ instances: [] as Array<{ options: Record<string, unknown>; write: ReturnType<typeof vi.fn> }> }));
vi.mock("xterm", () => ({ Terminal: function (options: Record<string, unknown>) {
  const terminal = { options: { ...options }, write: vi.fn(), writeln: vi.fn(), loadAddon: vi.fn(), open: vi.fn(), dispose: vi.fn(), attachCustomKeyEventHandler: vi.fn(), onData: vi.fn(() => ({ dispose: vi.fn() })), focus: vi.fn(), clear: vi.fn(), reset: vi.fn() };
  terminalState.instances.push(terminal); return terminal;
} }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: function () { return { fit: vi.fn(), proposeDimensions: () => ({ cols: 100, rows: 30 }) }; } }));
beforeEach(() => {
  mockBridge.reset(); mockBridge.install(); terminalState.instances = [];
  updateAppearance({ theme: "dark", terminalScheme: "oars", accent: "studio", fontSize: 13, font: "system" });
});
function shellHandlers(exit = 0) {
  mockBridge.setHandler("oars.history.shellSetup", payload => payload.execute ? { ok: true, channel: 42, connection_id: 7 } : { ok: true, command: "reviewed fixture installer", sha256: "plan-hash", connection_id: 7 });
  mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", connection_id: 7, history_full: false, channels: [{ id: 42, kind: "exec", command: "installer", data: "setup result", cursor: 12, dropped: 0, pending: 0, eof: true, exit }] } satisfies PollResult));
}
describe("shell setup approval and persistence", () => {
  it("previews without running, then saves the mode only after successful native completion", async () => {
    shellHandlers(); const setup = mockBridge.spyOn("oars.history.shellSetup"); const saved = mockBridge.spyOn("oars.servers.save"); const updated = vi.fn();
    render(<ShellIntegrationDialog server={mockBridge.state.servers[0]} connected onUpdated={updated} onClose={vi.fn()} />);
    await screen.findByText("reviewed fixture installer"); expect(setup.mock.calls.every(([payload]) => !payload.execute)).toBe(true); expect(saved).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Install integration"));
    await waitFor(() => expect(setup).toHaveBeenCalledWith({ server_id: mockBridge.state.servers[0].id, shell: "bash", execute: true, expected_sha256: "plan-hash", connection_id: 7 }));
    await waitFor(() => expect(saved).toHaveBeenCalledWith(expect.objectContaining({ history_shell: "bash" }))); expect(updated).toHaveBeenCalledOnce();
  });
  it("does not enable capture when installation fails", async () => {
    shellHandlers(3); const saved = mockBridge.spyOn("oars.servers.save");
    render(<ShellIntegrationDialog server={mockBridge.state.servers[0]} connected onUpdated={vi.fn()} onClose={vi.fn()} />);
    await screen.findByText("reviewed fixture installer"); fireEvent.click(screen.getByText("Install integration"));
    await screen.findByText("Setup did not confirm success. Shell history was not enabled."); expect(saved).not.toHaveBeenCalled();
  });
  it("disables current and future capture without disconnecting the session", async () => {
    shellHandlers(); const server = { ...mockBridge.state.servers[0], history_shell: "zsh" as const }; mockBridge.state.servers[0] = server;
    const setup = mockBridge.spyOn("oars.history.shellSetup"); const disconnect = mockBridge.spyOn("oars.ssh.disconnect");
    render(<ShellIntegrationDialog server={server} connected onUpdated={vi.fn()} onClose={vi.fn()} />);
    fireEvent.click(screen.getByText("Disable shell history"));
    await waitFor(() => expect(setup).toHaveBeenCalledWith({ server_id: server.id, shell: "off", execute: true })); expect(disconnect).not.toHaveBeenCalled();
  });
});
it("updates open terminal appearance without reconnecting or mixing exec bytes into the shell", async () => {
  const server = { ...mockBridge.state.servers[0], auth_method: "agent" as const };
  mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", connection_id: 1, channels: [{ id: 0, kind: "shell", command: "", data: "shell-only", cursor: 10, dropped: 0, pending: 0, eof: false, exit: null }, { id: 2, kind: "exec", command: "echo exec", data: "exec-only", cursor: 9, dropped: 0, pending: 0, eof: true, exit: 0 }] } satisfies PollResult));
  const connect = mockBridge.spyOn("oars.ssh.connect"); render(<TerminalTab server={server} onStatus={vi.fn()} />);
  await waitFor(() => expect(terminalState.instances[0].write).toHaveBeenCalledWith("shell-only")); expect(terminalState.instances[0].write).not.toHaveBeenCalledWith("exec-only");
  act(() => { updateAppearance({ terminalScheme: "solarized", theme: "light", fontSize: 18 }); });
  expect(terminalState.instances[0].options.theme).toMatchObject({ background: "#fdf6e3", foreground: "#657b83" }); expect(terminalState.instances[0].options.fontSize).toBe(18); expect(terminalState.instances).toHaveLength(1); expect(connect).toHaveBeenCalledTimes(1);
});

it("offers named user results and excludes internal probes from the terminal picker", async () => {
  const server = { ...mockBridge.state.servers[0], auth_method: "agent" as const };
  const base = { kind: "exec" as const, data: "", cursor: 0, dropped: 0, pending: 0, eof: true, exit: 0 };
  mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", connection_id: 1, channels: [{ ...base, id: 1, command: "internal log scan", user_visible: false }, { ...base, id: 2, command: "systemctl status nginx", user_visible: true }] } satisfies PollResult));
  render(<TerminalTab server={server} onStatus={vi.fn()} />);
  const picker = await screen.findByRole("combobox", { name: "Command output" });
  fireEvent.click(picker);
  expect(await screen.findByRole("option", { name: "systemctl status nginx · exit 0" })).toBeTruthy();
  expect(screen.queryByRole("option", { name: /internal log scan/ })).toBeNull();
});

import { AppearanceSettings } from "./components/AppearanceSettings";
it("keeps preferences across sections and updates the terminal preview in place", async () => {
  const onData = vi.fn();
  render(<AppearanceSettings onClose={vi.fn()} onData={onData} />);
  fireEvent.click(screen.getByRole("radio", { name: "Light" }));
  fireEvent.click(screen.getByRole("radio", { name: "Violet" }));
  expect(JSON.parse(localStorage.getItem("oars.theme")!)).toMatchObject({ theme: "light", accent: "violet" });
  fireEvent.click(screen.getByRole("button", { name: "Terminal" }));
  fireEvent.change(screen.getByLabelText("Font size"), { target: { value: "18" } });
  expect(terminalState.instances).toHaveLength(1);
  expect(terminalState.instances[0].options.fontSize).toBe(18);
  fireEvent.click(screen.getByRole("button", { name: "Appearance" }));
  expect((screen.getByRole("radio", { name: "Violet" }) as HTMLInputElement).checked).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "Data" }));
  fireEvent.click(screen.getByRole("button", { name: "Open data transfer" }));
  expect(onData).toHaveBeenCalledOnce();
});
