import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VncTab } from "./VncTab";
import { mockBridge } from "./test/mock-bridge";

const rfbState = vi.hoisted(() => ({ disconnects: [] as ReturnType<typeof vi.fn>[], instances: [] as Array<EventTarget & { disconnect: ReturnType<typeof vi.fn>; scaleViewport: boolean }> }));
vi.mock("@novnc/novnc", () => ({ default: class MockRfb extends EventTarget {
  disconnect = vi.fn();
  scaleViewport = true;
  constructor(target: HTMLElement) {
    super(); target.appendChild(document.createElement("canvas")); rfbState.instances.push(this); rfbState.disconnects.push(this.disconnect);
  }
} }));
let fullscreenElement: Element | null;
let request: ReturnType<typeof vi.fn>;
let exit: ReturnType<typeof vi.fn>;
function changeFullscreen(element: Element | null) {
  fullscreenElement = element;
  document.dispatchEvent(new Event("fullscreenchange"));
}
beforeEach(() => {
  mockBridge.reset(); mockBridge.install(); rfbState.instances = []; rfbState.disconnects = []; fullscreenElement = null;
  mockBridge.setHandler("oars.vnc.probe", () => ({ ok: true, x11vnc: true, tigervnc: false, desktop_installed: true, desktop_running: true, desktop_name: "XFCE", window_manager_running: true, listening: [{ port: 5900, process: "x11vnc" }] }));
  mockBridge.setHandler("oars.vnc.start", () => ({ ok: true, tunnel_id: 1, ws_port: 6080, token: "fixture-token" }));
  mockBridge.setHandler("oars.vnc.poll", () => ({ ok: true, state: "open", bytes_up: 0, bytes_down: 0 }));
  Object.defineProperty(document, "fullscreenElement", { configurable: true, get: () => fullscreenElement });
  Object.defineProperty(document, "fullscreenEnabled", { configurable: true, value: true });
  request = vi.fn(function(this: HTMLElement) { changeFullscreen(this); return Promise.resolve(); });
  exit = vi.fn(() => { changeFullscreen(null); return Promise.resolve(); });
  Object.defineProperty(HTMLElement.prototype, "requestFullscreen", { configurable: true, value: request });
  Object.defineProperty(document, "exitFullscreen", { configurable: true, value: exit });
});
afterEach(() => {
  delete (HTMLElement.prototype as Partial<HTMLElement>).requestFullscreen;
  for (const key of ["fullscreenElement", "fullscreenEnabled", "exitFullscreen"]) Reflect.deleteProperty(document, key);
});

describe("VNC full screen", () => {
  it("enters and exits with the same canvas, RFB connection and scale setting", async () => {
    const start = mockBridge.spyOn("oars.vnc.start"); const stop = mockBridge.spyOn("oars.vnc.stop");
    render(<VncTab serverId="fixture" />);
    fireEvent.click(screen.getByTestId("vnc-connect"));
    await waitFor(() => expect(rfbState.instances).toHaveLength(1));
    act(() => rfbState.instances[0].dispatchEvent(new Event("connect")));
    fireEvent.click(screen.getByTestId("vnc-scale-100"));
    const canvas = screen.getByTestId("vnc-rfb-target").firstChild;
    fireEvent.click(screen.getByRole("button", { name: /^Full screen$/ }));
    await screen.findByRole("button", { name: "Exit full screen" });
    expect(fullscreenElement).toBe(screen.getByTestId("vnc-tab"));
    fireEvent.click(screen.getByRole("button", { name: "Exit full screen" }));
    await screen.findByRole("button", { name: /^Full screen$/ });
    expect(screen.getByTestId("vnc-rfb-target").firstChild).toBe(canvas);
    expect(rfbState.instances).toHaveLength(1);
    expect(rfbState.instances[0].scaleViewport).toBe(false);
    expect(rfbState.disconnects[0]).not.toHaveBeenCalled();
    expect(start).toHaveBeenCalledOnce(); expect(stop).not.toHaveBeenCalled();
  });
  it("consumes Escape before remote keyboard handlers, including keyup after exit", async () => {
    render(<VncTab serverId="fixture" />);
    fireEvent.click(screen.getByTestId("vnc-fullscreen"));
    await screen.findByText("Exit full screen");
    const remoteKey = vi.fn();
    const target = screen.getByTestId("vnc-rfb-target");
    target.addEventListener("keydown", remoteKey); target.addEventListener("keyup", remoteKey);
    fireEvent.keyDown(target, { key: "Escape" }); fireEvent.keyUp(target, { key: "Escape" });
    await waitFor(() => expect(fullscreenElement).toBeNull());
    expect(remoteKey).not.toHaveBeenCalled();
  });
  it("keeps the password dialog in the fullscreen subtree and routes DOM Escape to it", async () => {
    render(<VncTab serverId="fixture" />);
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
    fireEvent.click(screen.getByTestId("vnc-password-manage"));
    const dialog = await screen.findByRole("dialog");
    expect(fullscreenElement?.contains(dialog)).toBe(true);
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(fullscreenElement).toBe(screen.getByTestId("vnc-tab")); expect(exit).not.toHaveBeenCalled();
  });
  it("reports a rejected request without claiming full screen", async () => {
    request.mockRejectedValueOnce(new Error("Request denied"));
    render(<VncTab serverId="fixture" />); fireEvent.click(screen.getByTestId("vnc-fullscreen"));
    await screen.findByText("Could not open full screen: Request denied");
    expect(screen.getByTestId("vnc-fullscreen").getAttribute("aria-pressed")).toBe("false");
    expect((screen.getByTestId("vnc-fullscreen") as HTMLButtonElement).disabled).toBe(false);
  });
  it("tracks browser exit and closes full screen when the pane is hidden", async () => {
    const { container } = render(<div><VncTab serverId="fixture" /></div>);
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
    act(() => changeFullscreen(null)); await screen.findByRole("button", { name: /^Full screen$/ });
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
    act(() => { (container.firstElementChild as HTMLElement).hidden = true; });
    await waitFor(() => expect(fullscreenElement).toBeNull());
  });
  it("exits on server switch and on unmount", async () => {
    const { rerender, unmount } = render(<VncTab serverId="first" />);
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
    rerender(<VncTab serverId="second" />);
    await waitFor(() => expect(fullscreenElement).toBeNull());
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
    unmount(); expect(fullscreenElement).toBeNull();
  });
  it("cleans up a request that finishes after unmount", async () => {
    let finish: () => void = () => {};
    request.mockImplementationOnce(function(this: HTMLElement) { const target = this; return new Promise<void>(resolve => { finish = () => { changeFullscreen(target); resolve(); }; }); });
    const { unmount } = render(<VncTab serverId="fixture" />);
    fireEvent.click(screen.getByTestId("vnc-fullscreen")); unmount();
    await act(async () => { finish(); });
    expect(fullscreenElement).toBeNull();
  });
});

it("reports unsupported full screen without changing the VNC view", async () => {
  Object.defineProperty(document, "fullscreenEnabled", { configurable: true, value: false });
  render(<VncTab serverId="fixture" />);
  fireEvent.click(screen.getByTestId("vnc-fullscreen"));
  await screen.findByText(/VNC full screen is unavailable/);
  expect(request).not.toHaveBeenCalled();
  expect(screen.getByTestId("vnc-fullscreen").getAttribute("aria-pressed")).toBe("false");
});

it("keeps a rejected exit retryable", async () => {
  render(<VncTab serverId="fixture" />);
  fireEvent.click(screen.getByTestId("vnc-fullscreen")); await screen.findByText("Exit full screen");
  exit.mockRejectedValueOnce(new Error("Exit denied"));
  fireEvent.click(screen.getByTestId("vnc-fullscreen"));
  await screen.findByText("Could not exit full screen: Exit denied");
  expect(fullscreenElement).toBe(screen.getByTestId("vnc-tab"));
  expect((screen.getByTestId("vnc-fullscreen") as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(screen.getByTestId("vnc-fullscreen"));
  await waitFor(() => expect(fullscreenElement).toBeNull());
});

it("allows Escape during a pending entry transition", async () => {
  let finish: () => void = () => {};
  request.mockImplementationOnce(function(this: HTMLElement) {
    changeFullscreen(this);
    return new Promise<void>(resolve => { finish = resolve; });
  });
  render(<VncTab serverId="fixture" />);
  fireEvent.click(screen.getByTestId("vnc-fullscreen"));
  await screen.findByText("Exit full screen");
  fireEvent.keyDown(screen.getByTestId("vnc-rfb-target"), { key: "Escape" });
  await waitFor(() => expect(fullscreenElement).toBeNull());
  await act(async () => finish());
  expect(fullscreenElement).toBeNull();
});
