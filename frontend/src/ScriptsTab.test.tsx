// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScriptsTab } from "./ScriptsTab";
import type { Script, Server } from "./types";

const bridgeMocks = vi.hoisted(() => ({
  list: vi.fn(),
  save: vi.fn(),
  deleteScript: vi.fn(),
  run: vi.fn(),
  validate: vi.fn(),
  broadcastPrepare: vi.fn(),
  broadcast: vi.fn(),
  broadcastPrepareCancel: vi.fn(),
  broadcastPoll: vi.fn(),
  broadcastCancel: vi.fn(),
  poll: vi.fn(),
  closeChannel: vi.fn(),
}));

vi.mock("./bridge", () => ({
  BridgeError: class BridgeError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  },
  api: {
    scripts: {
      list: bridgeMocks.list,
      save: bridgeMocks.save,
      delete: bridgeMocks.deleteScript,
      run: bridgeMocks.run,
      validate: bridgeMocks.validate,
      broadcastPrepare: bridgeMocks.broadcastPrepare,
      broadcast: bridgeMocks.broadcast,
      broadcastPrepareCancel: bridgeMocks.broadcastPrepareCancel,
      broadcastPoll: bridgeMocks.broadcastPoll,
      broadcastCancel: bridgeMocks.broadcastCancel,
    },
    ssh: {
      poll: bridgeMocks.poll,
      closeChannel: bridgeMocks.closeChannel,
    },
  },
}));

const server: Server = {
  id: "srv-1",
  name: "Production API",
  host: "api.internal.example",
  port: 22,
  user: "deploy",
  auth_method: "key",
  key_path: "~/.ssh/id_ed25519",
  key_has_passphrase: false,
  host_fingerprint: null,
  group: "Production",
  tags: [],
  via_server_id: null,
  created_at: 0,
  updated_at: 0,
};

const offlineServer: Server = {
  ...server,
  id: "srv-2",
  name: "Staging API",
  host: "staging.internal.example",
  group: "Staging",
};

const script: Script = {
  id: "script-1",
  name: "Tail logs",
  description: "Read the current service log",
  tags: ["logs"],
  color: "#3f6d7a",
  body: "tail -n 50 /var/log/{{service}}.log",
  variables: [{ name: "service", label: "Service", secret_default: false }],
  created_at: 0,
  updated_at: 0,
  run_count: 0,
  last_run_at: null,
};

function renderScripts() {
  return render(
    <ScriptsTab
      serverId={server.id}
      servers={[server]}
      connected
      statuses={new Map([[server.id, "ready"]])}
    />
  );
}

async function startRun(value: string, secret = false) {
  const user = userEvent.setup();
  await user.click((await screen.findAllByRole("button", { name: "Run" }))[0]);
  const dialog = screen.getByRole("dialog");
  const input = within(dialog).getByLabelText(/service/i);
  await user.clear(input);
  await user.type(input, value);
  if (secret) await user.click(within(dialog).getByRole("checkbox", { name: /secret/i }));
  await user.click(within(dialog).getByRole("button", { name: "Run" }));
}

beforeEach(() => {
  vi.clearAllMocks();
  bridgeMocks.list.mockResolvedValue({ ok: true, scripts: [script] });
  bridgeMocks.validate.mockResolvedValue({ ok: true });
  bridgeMocks.run.mockResolvedValue({ ok: true, channel: 41 });
  bridgeMocks.poll.mockResolvedValue({
    ok: true,
    status: "ready",
    channels: [{ id: 41, kind: "exec", command: "", cursor: 7, dropped: 0, pending: 0, eof: true, exit: 0, data: "done\n" }],
  });
  bridgeMocks.closeChannel.mockResolvedValue({ ok: true });
  bridgeMocks.broadcastPrepareCancel.mockResolvedValue({ ok: true });
  bridgeMocks.broadcastCancel.mockResolvedValue({ ok: true });
});

afterEach(() => cleanup());

describe("Scripts workspace", () => {
  it("loads the library without changing hook order", async () => {
    renderScripts();
    expect(await screen.findAllByText("Tail logs")).toHaveLength(2);
    expect(screen.getByText(/Read the current service log/)).toBeTruthy();
  });

  it("does not prefill a promoted secret on the next run", async () => {
    renderScripts();
    await startRun("production-password", true);
    await screen.findByText("done", { selector: "pre" });
    await userEvent.click(screen.getByRole("button", { name: "Close output" }));
    await userEvent.click(screen.getByRole("button", { name: "Run" }));
    expect((within(screen.getByRole("dialog")).getByLabelText(/service/i) as HTMLInputElement).value).toBe("");
  });

  it("resets the absolute cursor and closes completed channels", async () => {
    renderScripts();
    await startRun("nginx");
    await waitFor(() => expect(bridgeMocks.poll).toHaveBeenCalledWith(server.id, [{ channel: 41, cursor: 0 }], false));
    await userEvent.click(screen.getByRole("button", { name: "Close output" }));
    await waitFor(() => expect(bridgeMocks.closeChannel).toHaveBeenCalledWith(server.id, 41));

    bridgeMocks.run.mockResolvedValueOnce({ ok: true, channel: 42 });
    bridgeMocks.poll.mockResolvedValueOnce({
      ok: true,
      status: "ready",
      channels: [{ id: 42, kind: "exec", command: "", cursor: 3, dropped: 0, pending: 0, eof: true, exit: 0, data: "again\n" }],
    });
    await startRun("php-fpm");
    await waitFor(() => expect(bridgeMocks.poll).toHaveBeenCalledWith(server.id, [{ channel: 42, cursor: 0 }], false));
  });

  it("keeps focus in the field being edited", async () => {
    const user = userEvent.setup();
    renderScripts();
    await user.click(await screen.findByRole("button", { name: "Edit" }));
    const description = screen.getByLabelText("Description");
    await user.click(description);
    await user.type(description, " now");
    expect(document.activeElement).toBe(description);
  });

  it("offers saved variables after an opening double brace", async () => {
    const user = userEvent.setup();
    renderScripts();
    await user.click(await screen.findByRole("button", { name: "Edit" }));
    const body = screen.getByLabelText(/Command body/) as HTMLTextAreaElement;
    const nextBody = `${body.value}\necho {{ser`;
    fireEvent.change(body, { target: { value: nextBody, selectionStart: nextBody.length } });
    const suggestion = await screen.findByRole("option", { name: /service/i });
    await user.click(suggestion);
    expect(body.value).toContain("echo {{service}}");
  });

  it("shows a no-match state and clears combined filters", async () => {
    const user = userEvent.setup();
    renderScripts();
    await screen.findByText(/Read the current service log/);
    await user.selectOptions(screen.getByLabelText("Filter scripts by tag"), "logs");
    await user.type(screen.getByLabelText("Search scripts"), "deploy");
    expect(await screen.findByRole("heading", { name: "No matching scripts" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText(/Read the current service log/)).toBeTruthy();
  });

  it("keeps unavailable broadcast targets visible and disabled", async () => {
    const user = userEvent.setup();
    render(
      <ScriptsTab
        serverId={server.id}
        servers={[server, offlineServer]}
        connected
        statuses={new Map([[server.id, "ready"], [offlineServer.id, "closed"]])}
      />
    );
    await user.click(await screen.findByRole("button", { name: /Run on multiple servers/ }));
    const staging = screen.getByRole("checkbox", { name: /Staging API/ }) as HTMLInputElement;
    expect(staging.disabled).toBe(true);
    expect(within(screen.getByRole("dialog")).getByText("Unavailable")).toBeTruthy();
  });

  it("requires a second confirmation for destructive broadcasts", async () => {
    const destructiveScript = { ...script, tags: ["logs", "destructive"] };
    bridgeMocks.list.mockResolvedValue({ ok: true, scripts: [destructiveScript] });
    bridgeMocks.broadcastPrepare.mockResolvedValue({
      ok: true,
      preview_id: 7,
      script_id: destructiveScript.id,
      script_name: destructiveScript.name,
      command: "bash -c 'tail -n 50 /var/log/nginx.log'",
      redacted_command: "bash -c 'tail -n 50 /var/log/nginx.log'",
      servers: [{ server_id: server.id }],
      destructive: true,
      expires_at: Date.now() + 600_000,
    });
    bridgeMocks.broadcast.mockResolvedValue({ ok: true, run_id: 9 });
    bridgeMocks.broadcastPoll.mockResolvedValue({
      ok: true,
      run_id: 9,
      script_name: destructiveScript.name,
      canceled: false,
      done: true,
      servers: [{ server_id: server.id, status: "done", exit: 0, error: "", cursor: 0, gap: 0, eof: true, data: "" }],
    });

    const user = userEvent.setup();
    renderScripts();
    await user.click(await screen.findByRole("button", { name: /Run on multiple servers/ }));
    await user.click(screen.getByRole("checkbox", { name: /Production API/ }));
    await user.click(screen.getByRole("button", { name: "Continue with 1 server" }));
    await user.type(screen.getByLabelText(/service/i), "nginx");
    await user.click(screen.getByRole("button", { name: "Preview command" }));
    await user.click(await screen.findByRole("button", { name: "Continue to safety check" }));
    expect(bridgeMocks.broadcast).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Confirm destructive broadcast" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Confirm destructive run" }));
    await waitFor(() => expect(bridgeMocks.broadcast).toHaveBeenCalledWith(7));
  });

  it("closes an owned run channel when the view unmounts", async () => {
    const view = renderScripts();
    await startRun("nginx");
    await screen.findByText("done", { selector: "pre" });
    view.unmount();
    await waitFor(() => expect(bridgeMocks.closeChannel).toHaveBeenCalledWith(server.id, 41));
  });
});
