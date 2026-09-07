import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { groupMembers, fleetRollup, moveGroupProfiles, validateGroupName } from "./fleet";
import { readAppearance, updateAppearance, terminalTheme } from "./appearance";
import { GroupEditDialog } from "./components/GroupEditDialog";
import { GroupView } from "./components/GroupView";
import { useFleetMove } from "./useFleetMove";
import { mockBridge } from "./test/mock-bridge";

beforeEach(() => { mockBridge.reset(); mockBridge.install(); localStorage.clear(); });
afterEach(() => { vi.unstubAllGlobals(); });
describe("fleet operations", () => {
  it("derives exclusive groups, rollups, and valid one-level paths", () => {
    const servers = mockBridge.state.servers.map((server, i) => ({ ...server, group: i === 0 ? "clients/acme" : "" }));
    expect(groupMembers(servers, "clients/acme")).toHaveLength(1);
    expect(fleetRollup(servers, new Map([[servers[0].id, "ready"]]))).toEqual({ total: servers.length, connected: 1, errors: 0 });
    expect(validateGroupName("a/b/c")).toBeTruthy(); expect(validateGroupName("a\n")).toBeTruthy(); expect(validateGroupName("a//b")).toBeTruthy(); expect(validateGroupName("clients/acme")).toBeNull();
  });
  it("moves profiles without discarding auth, tags, jump hosts, or shell-history choices", async () => {
    const server = { ...mockBridge.state.servers[0], tags: ["production"], via_server_id: "jump", history_shell: "zsh" as const };
    const save = mockBridge.spyOn("oars.servers.save"); const result = await moveGroupProfiles([server], "clients/acme");
    expect(result.failures).toHaveLength(0); expect(save).toHaveBeenCalledWith(expect.objectContaining({ id: server.id, auth_method: server.auth_method, key_path: server.key_path, tags: ["production"], via_server_id: "jump", history_shell: "zsh", group: "clients/acme" }));
  });
  it("deletes a group by moving profiles and reports partial save failures", async () => {
    const servers = [mockBridge.state.servers[0], { ...mockBridge.state.servers[0], id: "second", name: "Second server" }].map(server => ({ ...server, group: "prod" }));
    mockBridge.queueResponse("oars.servers.save", { server: { ...servers[0], group: "" } });
    mockBridge.queueResponse("oars.servers.save", { ok: false, error: "Disk full" });
    const remove = mockBridge.spyOn("oars.servers.delete"); const update = vi.fn(); const close = vi.fn();
    render(<GroupEditDialog servers={servers} group="prod" remove onUpdated={update} onClose={close} />);
    fireEvent.click(screen.getByText("Move servers to Ungrouped"));
    await screen.findByText(/Retry failed profiles/); expect(update).toHaveBeenCalledWith([{ ...servers[0], group: "" }]); expect(remove).not.toHaveBeenCalled(); expect(close).not.toHaveBeenCalled();
  });
  it("bounds group monitoring to 12 visible cards and exposes the next page", async () => {
    vi.stubGlobal("IntersectionObserver", undefined);
    const servers = Array.from({ length: 25 }, (_, i) => ({ ...mockBridge.state.servers[0], id: `s${i}`, name: `Server ${i}`, group: "prod" }));
    const poll = mockBridge.spyOn("oars.ssh.poll"); const onStatus = vi.fn();
    mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "closed", channels: [] }));
    render(<GroupView group="prod" servers={servers} statuses={new Map()} onStatus={onStatus} onOpen={vi.fn()} onOpenAll={vi.fn()} onRunScript={vi.fn()} onUpdated={vi.fn()} onBack={vi.fn()} />);
    await waitFor(() => expect(poll).toHaveBeenCalledTimes(12)); expect(screen.queryByRole("button", { name: /^Open Server 12$/ })).toBeNull();
    fireEvent.click(screen.getByText("Next")); await screen.findByRole("button", { name: "Open Server 12" });
    await waitFor(() => expect(poll).toHaveBeenCalledTimes(24));
  });
  it("moves on a valid pointer drop and cancels on Escape", () => {
    const moved = vi.fn(); const server = mockBridge.state.servers[0];
    function Harness() { const move = useFleetMove(moved); return <><button onPointerDown={event => move.onPointerDown(event, server)} onPointerMove={move.onPointerMove} onPointerUp={move.onPointerUp}>Server</button><div data-fleet-group-drop="prod">Group</div></>; }
    render(<Harness />); Object.defineProperty(document, "elementFromPoint", { configurable: true, value: () => screen.getByText("Group") });
    const button = screen.getByText("Server");
    fireEvent.pointerDown(button, { button: 0, pointerId: 1, clientX: 0, clientY: 0 }); fireEvent.pointerMove(button, { pointerId: 1, clientX: 40, clientY: 40 }); fireEvent.pointerUp(button, { pointerId: 1, clientX: 40, clientY: 40 });
    expect(moved).toHaveBeenCalledWith(server, "prod"); moved.mockClear();
    fireEvent.pointerDown(button, { button: 0, pointerId: 2, clientX: 0, clientY: 0 }); fireEvent.pointerMove(button, { pointerId: 2, clientX: 40, clientY: 40 }); fireEvent.keyDown(window, { key: "Escape" }); fireEvent.pointerUp(button, { pointerId: 2, clientX: 40, clientY: 40 }); expect(moved).not.toHaveBeenCalled();
  });
});
describe("appearance contract", () => {
  it("validates stored choices and preserves the legacy theme", () => {
    localStorage.setItem("oars:theme", "light"); localStorage.setItem("oars.theme", JSON.stringify({ fontSize: -2, terminalScheme: "invalid", accent: "invalid" }));
    expect(readAppearance()).toMatchObject({ theme: "light", fontSize: 13, terminalScheme: "oars", accent: "studio" });
    localStorage.setItem("oars.theme", "null"); expect(readAppearance().theme).toBe("light");
  });
  it("persists all schemes and chooses Solarized foreground/background as a pair", () => {
    for (const scheme of ["oars", "one-dark", "solarized", "ansi"] as const) {
      updateAppearance({ theme: "dark", terminalScheme: scheme, accent: "violet", fontSize: 17 });
      expect(readAppearance()).toMatchObject({ terminalScheme: scheme, accent: "violet", fontSize: 17 }); expect(terminalTheme(readAppearance()).background).toBeTruthy();
    }
    expect(terminalTheme({ terminalScheme: "solarized", theme: "light" })).toMatchObject({ background: "#fdf6e3", foreground: "#657b83" });
    expect(terminalTheme({ terminalScheme: "solarized", theme: "dark" })).toMatchObject({ background: "#002b36", foreground: "#839496" });
  });
});

it("virtualizes a 500-profile sidebar while retaining group headers", async () => {
  const { FleetList } = await import("./components/FleetList");
  const servers = Array.from({ length: 500 }, (_, index) => ({ ...mockBridge.state.servers[0], id: `large-${index}`, name: `Large server ${index}` }));
  const start = performance.now();
  render(<div style={{ height: 400 }}><FleetList groups={[{ key: "all", path: "", label: "Ungrouped", entries: servers }]} collapsed={new Set()} expandAll={false} empty="Empty" renderGroup={group => <h2>{group.label}</h2>} renderServer={server => <div role="listitem">{server.name}</div>} /></div>);
  await screen.findByRole("heading", { name: "Ungrouped" });
  const mounted = screen.getAllByRole("listitem"); expect(mounted.length).toBeLessThan(40); expect(mounted.length).toBeGreaterThan(0);
  console.info(`500-profile sidebar: ${mounted.length} mounted rows; initial render ${(performance.now() - start).toFixed(1)} ms in jsdom`);
});
