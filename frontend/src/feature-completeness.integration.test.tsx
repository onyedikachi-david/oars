import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VaultTab } from "./VaultTab";
import { AgentTab } from "./AgentTab";
import { HistoryTab } from "./HistoryTab";
import { mockBridge } from "./test/mock-bridge";
import type { AgentListResult, HistoryEntry, VaultImportResult } from "./types";

beforeEach(() => { mockBridge.reset(); mockBridge.install(); });
const change = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const password = "correct horse battery";
const preview: VaultImportResult = { ok: true, preview: { errors: [], reports: [{ name: "servers", incoming: 1, new: 0, updated: 1, conflicts: [{ key: "servers:s1", reason: "Endpoint changed" }] }] } };

describe("Vault typed user path", () => {
  it("sends the save dialog path and rejects short or mismatched passwords", async () => {
    const save = mockBridge.spyOn("native-sdk.dialog.saveFile");
    const exported = mockBridge.spyOn("oars.vault.export");
    render(<VaultTab />);
    fireEvent.click(screen.getByText("Export…"));
    await screen.findByRole("alert"); expect(save).not.toHaveBeenCalled();
    change("Export password (at least 12 characters)", password); change("Repeat export password", password);
    fireEvent.click(screen.getByText("Export…"));
    await waitFor(() => expect(exported).toHaveBeenCalledWith(expect.objectContaining({ path: "/mock/saved/file.tar.gz", password, sections: expect.arrayContaining(["servers"]) })));
    await screen.findByText(/Exported 7 sections/);
  });
  it("does not export when the save dialog is cancelled", async () => {
    mockBridge.queueResponse("native-sdk.dialog.saveFile", null);
    const exported = mockBridge.spyOn("oars.vault.export"); render(<VaultTab />);
    change("Export password (at least 12 characters)", password); change("Repeat export password", password);
    fireEvent.click(screen.getByText("Export…"));
    await waitFor(() => expect((screen.getByText("Export…") as HTMLButtonElement).disabled).toBe(false));
    expect(exported).not.toHaveBeenCalled();
  });
  it("keeps preview separate from apply and submits explicit conflict choices with the same source", async () => {
    mockBridge.queueResponse("oars.vault.import", preview);
    const apply = mockBridge.spyOn("oars.vault.importConfirm"); const imported = vi.fn();
    render(<VaultTab onImported={imported} />);
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    change("Import password (leave empty for plain JSON)", password);
    fireEvent.click(screen.getByText("Pick & preview")); await screen.findByText("Confirm import");
    expect(apply).not.toHaveBeenCalled(); expect(screen.queryByText(/Import applied/)).toBeNull();
    const user = userEvent.setup();
    await user.click(screen.getByRole("combobox", { name: /Endpoint changed/ }));
    await user.click(await screen.findByRole("option", { name: "Import as new" }));
    fireEvent.click(screen.getByText("Confirm import"));
    await waitFor(() => expect(apply).toHaveBeenCalledWith({ path: "/mock/selected/path.txt", password, keep_local: [], import_as_new: ["servers:s1"] }));
    await screen.findByText(/Import applied/); expect(imported).toHaveBeenCalledOnce();
  });
  it("keeps a rejected apply retryable and cancels without a native mutation", async () => {
    mockBridge.queueResponse("oars.vault.import", preview);
    mockBridge.queueResponse("oars.vault.importConfirm", { ok: false, error: "File changed" });
    const apply = mockBridge.spyOn("oars.vault.importConfirm"); render(<VaultTab />);
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    fireEvent.click(screen.getByText("Pick & preview")); fireEvent.click(await screen.findByText("Confirm import"));
    await screen.findByText("File changed"); expect(screen.queryByText(/Import applied/)).toBeNull();
    fireEvent.click(screen.getByText("Cancel")); expect(apply).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Confirm import")).toBeNull();
  });
  it("does not offer apply after an invalid preview or a native error", async () => {
    mockBridge.queueResponse("oars.vault.import", { ok: false, error: "Wrong password" });
    render(<VaultTab />); fireEvent.click(screen.getByRole("button", { name: "Import" })); fireEvent.click(screen.getByText("Pick & preview"));
    await screen.findByText("Wrong password"); expect(screen.queryByText("Confirm import")).toBeNull();
  });
});

describe("Agent identities and forwarding", () => {
  it("renders native identities and requires shell-restart confirmation", async () => {
    const result: AgentListResult = { ok: true, identities: [{ kind: "ssh-ed25519", fingerprint_sha256: "SHA256:test", comment: "Laptop key" }] };
    mockBridge.queueResponse("oars.agent.list", result);
    mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", forwarding: false, channels: [] }));
    const forward = mockBridge.spyOn("oars.agent.forward");
    render(<AgentTab server={mockBridge.state.servers[0]} />);
    await screen.findByText("Laptop key"); expect(screen.getByText("SHA256:test")).toBeTruthy();
    fireEvent.click(screen.getByText("Enable forwarding…")); expect(forward).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Restart shell and enable"));
    await waitFor(() => expect(forward).toHaveBeenCalledWith({ server_id: mockBridge.state.servers[0].id, on: true }));
  });
  it("shows native hints and reads the real forwarding state after refusal", async () => {
    mockBridge.queueResponse("oars.agent.list", { ok: true, identities: [], error: "no agent" } satisfies AgentListResult);
    mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", forwarding: true, channels: [] }));
    mockBridge.queueResponse("oars.agent.forward", { ok: false, error: "Request refused" });
    render(<AgentTab server={mockBridge.state.servers[0]} />);
    await screen.findByText("no agent"); fireEvent.click(screen.getByText("Disable forwarding…")); fireEvent.click(screen.getByText("Restart shell and disable"));
    await screen.findByText("Request refused"); expect(screen.getByText("Enabled")).toBeTruthy();
  });
});

describe("History review and audit confirmation", () => {
  const entry = (): HistoryEntry => ({ id: "h1", operation_id: "op1", ts: 1700000000000000000, server_id: mockBridge.state.servers[0].id, kind: "exec", command: "printf hello", exit: 0, duration_ms: 20, output_snippet: "hello", redacted: false });
  it("reviews the exact command and server before replay and displays output", async () => {
    mockBridge.queueResponse("oars.history.list", { ok: true, entries: [entry()] });
    mockBridge.setHandler("oars.ssh.poll", () => ({ ok: true, status: "ready", channels: [{ id: 1, data: "hello again", cursor: 11, dropped: 0, eof: true, exit: 0, pending: 0, kind: "exec" }] }));
    const replay = mockBridge.spyOn("oars.history.replay"); render(<HistoryTab />);
    fireEvent.click(await screen.findByText("Replay")); expect(replay).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog"); expect(within(dialog).getByText("printf hello")).toBeTruthy(); expect(dialog.textContent).toContain(mockBridge.state.servers[0].host);
    fireEvent.click(within(dialog).getByText("Run command"));
    await waitFor(() => expect(replay).toHaveBeenCalledWith({ entry_id: "h1" })); await screen.findByText("hello again"); await screen.findByText(/Finished with exit code 0/);
  });
  it("blocks redacted replay, filters commands, and requires the user to type CLEAR", async () => {
    mockBridge.queueResponse("oars.history.list", { ok: true, entries: [entry(), { ...entry(), id: "h2", command: "TOKEN=•••• deploy", redacted: true }] });
    const clear = mockBridge.spyOn("oars.audit.clear"); render(<HistoryTab />);
    await screen.findByTitle("TOKEN=•••• deploy"); expect((screen.getAllByText("Replay")[1] as HTMLButtonElement).disabled).toBe(true);
    change("Search history and audit", "printf"); expect(screen.queryByText("TOKEN=•••• deploy")).toBeNull();
    fireEvent.click(screen.getByText("Clear audit…")); const button = screen.getByRole("button", { name: /^Clear audit$/ });
    expect((button as HTMLButtonElement).disabled).toBe(true); expect(clear).not.toHaveBeenCalled();
    change("Type CLEAR to confirm", "CLEAR"); fireEvent.click(button);
    await waitFor(() => expect(clear).toHaveBeenCalledWith({ confirm: "CLEAR" }));
  });
  it("surfaces audit read errors", async () => {
    mockBridge.queueResponse("oars.audit.list", { ok: false, error: "Journal unreadable" });
    render(<HistoryTab />); await screen.findByText(/Journal unreadable/);
  });
});
