import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UpdateExperience, downloadPercent } from "./UpdateDialog";
import { updateApi, useUpdates, type UpdateStatus } from "../updates";
vi.mock("../updates", () => ({ useUpdates: vi.fn(), updateApi: { install: vi.fn(), cancel: vi.fn(), check: vi.fn(), releaseNotes: vi.fn() } }));
const fixture: UpdateStatus = { mode: "sparkle", state: "available", current_version: "0.6.0", latest_version: "0.7.0", release_notes: "• Keep working during downloads.\n• Choose when to install.", error: "", automatic_checks: true, automatic_downloads: true, can_check: false, can_install: true, can_resume: false, can_cancel: false, busy: false, install_when_idle: false, downloaded_bytes: 0, total_bytes: 0 };
beforeEach(() => { vi.mocked(useUpdates).mockReturnValue({ ...fixture }); for (const method of Object.values(updateApi)) vi.mocked(method).mockResolvedValue({ ok: true } as never); });
afterEach(() => { cleanup(); vi.clearAllMocks(); });
describe("in-app update experience", () => {
  it("shows the version change and release notes as inert text", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, release_notes: '<img src=x onerror="alert(1)">' });
    render(<UpdateExperience onOpen={vi.fn()} />);
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByLabelText("Version 0.6.0 to 0.7.0")).toBeTruthy();
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeTruthy();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
  it("installs now through the native action and closes only after success", async () => {
    render(<UpdateExperience onOpen={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Install and restart" }));
    expect(updateApi.install).toHaveBeenCalledWith(false);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
  it("allows scheduling during active work but blocks immediate restart", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, busy: true });
    render(<UpdateExperience onOpen={vi.fn()} />);
    expect((await screen.findByRole("button", { name: "Install and restart" }) as HTMLButtonElement).disabled).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Install when idle" }));
    expect(updateApi.install).toHaveBeenCalledWith(true);
  });
  it("shows measured progress and cancels through the backend", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, state: "downloading", can_cancel: true, downloaded_bytes: 17, total_bytes: 100 });
    render(<UpdateExperience onOpen={vi.fn()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("progressbar").getAttribute("value")).toBe("17");
    await userEvent.click(screen.getByRole("button", { name: "Cancel download" }));
    expect(updateApi.cancel).toHaveBeenCalledOnce();
  });
  it("does not invent a percentage when the server omits its size", () => {
    expect(downloadPercent({ ...fixture, downloaded_bytes: 100 })).toBeUndefined();
    expect(downloadPercent({ ...fixture, downloaded_bytes: 120, total_bytes: 100 })).toBe(100);
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, state: "downloading" });
    render(<UpdateExperience onOpen={vi.fn()} />);
    expect(screen.getByRole("progressbar").hasAttribute("value")).toBe(false);
  });
  it("lets the user cancel a scheduled restart without reopening the dialog", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, state: "blocked", install_when_idle: true, can_cancel: true });
    render(<UpdateExperience onOpen={vi.fn()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Cancel scheduled install" }));
    expect(updateApi.cancel).toHaveBeenCalledOnce();
  });
  it("keeps the dialog and reports a rejected installation", async () => {
    vi.mocked(updateApi.install).mockRejectedValue(new Error("Work is still active."));
    render(<UpdateExperience onOpen={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Install and restart" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Work is still active.");
    expect(screen.getByRole("dialog")).toBeTruthy();
  });
  it("closes with Escape and does not automatically reopen on the next poll", async () => {
    const view = render(<UpdateExperience onOpen={vi.fn()} />);
    await screen.findByRole("dialog");
    await userEvent.keyboard("{Escape}");
    vi.mocked(useUpdates).mockReturnValue({ ...fixture });
    view.rerender(<UpdateExperience onOpen={vi.fn()} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(updateApi.cancel).not.toHaveBeenCalled();
  });
  it("leaves Linux upgrades with the package manager", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, mode: "homebrew", can_install: false });
    const open = vi.fn();
    render(<UpdateExperience onOpen={open} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "View update" }));
    expect(open).toHaveBeenCalledOnce();
    expect(updateApi.install).not.toHaveBeenCalled();
  });
});
