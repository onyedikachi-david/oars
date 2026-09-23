import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UpdateSettings } from "./UpdateSettings";
import { updateApi, useUpdates, type UpdateStatus } from "../updates";

vi.mock("../updates", () => ({
  useUpdates: vi.fn(),
  updateApi: { check: vi.fn(), preferences: vi.fn(), resume: vi.fn(), releaseNotes: vi.fn() },
}));
const fixture: UpdateStatus = {
  can_install: false, can_cancel: false, install_when_idle: false, downloaded_bytes: 0, total_bytes: 0, release_notes: "",
  mode: "sparkle", state: "idle", current_version: "0.7.0", latest_version: "", error: "",
  automatic_checks: true, automatic_downloads: true, can_check: true, can_resume: false, busy: false,
};
beforeEach(() => {
  vi.mocked(useUpdates).mockReturnValue({ ...fixture });
  for (const fn of Object.values(updateApi)) vi.mocked(fn).mockResolvedValue({ ok: true } as never);
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("update controls", () => {
  it("keeps downloads user-controlled and uses native checks", async () => {
    render(<UpdateSettings />);
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(updateApi.check).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByLabelText("Download updates in the background"));
    expect(updateApi.preferences).toHaveBeenCalledWith(true, false);
  });
  it("does not offer restart while work is active", () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, state: "blocked", can_resume: true, busy: true });
    render(<UpdateSettings />);
    expect((screen.getByRole("button", { name: "Restart to update" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("status").textContent).toContain("disconnect sessions");
  });
  it("resumes a deferred install once work is finished", async () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, state: "blocked", can_resume: true });
    render(<UpdateSettings />);
    await userEvent.click(screen.getByRole("button", { name: "Restart to update" }));
    expect(updateApi.resume).toHaveBeenCalledOnce();
  });
  it("leaves Linux Homebrew files to Homebrew", () => {
    vi.mocked(useUpdates).mockReturnValue({ ...fixture, mode: "homebrew", state: "available", latest_version: "0.8.0", automatic_downloads: false });
    render(<UpdateSettings />);
    expect(screen.getByText(/brew upgrade --cask/).textContent).toContain("onyedikachi-david/tap/oars");
    expect(screen.queryByLabelText("Download updates in the background")).toBeNull();
    expect(screen.queryByRole("button", { name: "Restart to update" })).toBeNull();
  });
  it("restores a preference when saving fails", async () => {
    vi.mocked(updateApi.preferences).mockRejectedValue(new Error("Could not save update preferences. Try again."));
    render(<UpdateSettings />);
    const control = screen.getByRole("switch", { name: "Download updates in the background" }) as HTMLInputElement;
    await userEvent.click(control);
    await screen.findByRole("alert");
    expect(control.checked).toBe(true);
  });
  it("reports action failures without claiming success", async () => {
    vi.mocked(updateApi.check).mockRejectedValue(new Error("Offline. Check your connection and try again."));
    render(<UpdateSettings />);
    await userEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Check your connection");
  });
});
