// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AiTab } from "./AiTab";
import type { AiProvider } from "./types";

const provider: AiProvider = {
  id: "aip-0123456789abcdef",
  name: "Primary",
  adapter: "openai_responses",
  tool_mode: "structured_result",
  base_url: "https://api.openai.com/v1",
  model: "gpt-test",
  instruction_role: null,
  structured_output: null,
  revision: 1,
  tested_at_ms: null,
  test_status: "untested",
};

interface Call {
  command: string;
  payload: unknown;
}

describe("AiTab credentials", () => {
  const calls: Call[] = [];
  let credentialStatus = "missing";

  beforeEach(() => {
    calls.length = 0;
    credentialStatus = "missing";
    window.zero = {
      invoke: vi.fn(async (command: string, payload?: unknown) => {
        calls.push({ command, payload });
        if (command === "oars.ai.provider.list") return { ok: true, providers: [provider] };
        if (command === "oars.ai.context.get") return { ok: true, state: "missing", context: null, stale: true };
        if (command === "oars.ai.credential.status") return { ok: true, status: credentialStatus };
        if (command === "oars.ai.credential.configure") {
          credentialStatus = "configured";
          return { ok: true, status: credentialStatus };
        }
        if (command === "oars.ai.credential.delete") {
          credentialStatus = "missing";
          return { ok: true, status: credentialStatus };
        }
        if (command === "oars.ai.provider.test") return { ok: true, operation_id: "provider-test-one", state: "queued" };
        if (command === "oars.ai.provider.testPoll") return { ok: true, stream_id: "provider-test-one", cursor: 2, dropped: 0, finished: true, state: "passed", events: [] };
        throw new Error(`unexpected command: ${command}`);
      }),
    };
  });

  afterEach(() => {
    cleanup();
    delete window.zero;
    delete document.documentElement.dataset.previewVariant;
    window.history.replaceState({}, "", "/");
  });

  it("keeps provider management visible while a new provider is edited", async () => {
    render(<AiTab serverId="server-one" />);

    const manage = await screen.findByRole("button", { name: /manage providers/i });
    const details = manage.closest("details") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    fireEvent.click(manage);

    const name = await screen.findByLabelText("Provider name") as HTMLInputElement;
    await waitFor(() => expect(details.open).toBe(true));
    fireEvent.change(name, { target: { value: "Secondary" } });
    expect((screen.getByLabelText("Provider name") as HTMLInputElement).value).toBe("Secondary");
    expect(details.open).toBe(true);
    expect(manage.getAttribute("aria-expanded")).toBe("true");
  });

  it("opens native credential management without putting a secret in WebView state or bridge payloads", async () => {
    const view = render(<AiTab serverId="server-one" />);
    fireEvent.click(await screen.findByRole("button", { name: "Configure credential" }));

    await screen.findByRole("button", { name: "Replace credential" });
    expect(view.container.querySelector('input[type="password"]')).toBeNull();
    const configure = calls.find((call) => call.command === "oars.ai.credential.configure");
    expect(configure?.payload).toMatchObject({ provider_id: provider.id });
    expect(JSON.stringify(configure?.payload)).not.toMatch(/secret|api[_-]?key/i);

    expect(screen.getByText(/can use provider quota/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Test provider · uses quota" }));
    await screen.findByText("Provider test passed.");
    const providerTest = calls.find((call) => call.command === "oars.ai.provider.test");
    expect(providerTest?.payload).toMatchObject({ provider_id: provider.id, expected_revision: provider.revision });
    expect(JSON.stringify(providerTest?.payload)).not.toMatch(/secret|api[_-]?key/i);

    fireEvent.click(screen.getByRole("button", { name: "Remove credential" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Configure credential" })).toBeTruthy());
    const remove = calls.find((call) => call.command === "oars.ai.credential.delete");
    expect(remove?.payload).toMatchObject({ provider_id: provider.id });
    expect(JSON.stringify(remove?.payload)).not.toMatch(/secret|api[_-]?key/i);
  });

  it("requires disclosure and destructive acknowledgement before it runs the frozen proposal", async () => {
    const readyProvider: AiProvider = { ...provider, test_status: "passed", tested_at_ms: 10 };
    credentialStatus = "configured";
    let turnPollCount = 0;
    window.zero = {
      invoke: vi.fn(async (command: string, payload?: unknown) => {
        calls.push({ command, payload });
        if (command === "oars.ai.provider.list") return { ok: true, providers: [readyProvider] };
        if (command === "oars.ai.credential.status") return { ok: true, status: "configured" };
        if (command === "oars.ai.context.get") return { ok: true, state: "ready", stale: false, updated_at_ms: 10, context: { server_id: "server-one", os: "Linux", hostname: "fixture", monitor: {}, active_logs: [], partial: false, errors: [], updated_at_ms: 10 } };
        if (command === "oars.ai.context.refresh") return { ok: true, operation_id: "context-before-proposal", state: "queued" };
        if (command === "oars.ai.context.poll") return { ok: true, stream_id: "context-before-proposal", cursor: 1, dropped: 0, finished: true, state: "ready", events: [] };
        if (command === "oars.servers.list") return { servers: [{ id: "server-one", name: "Fixture", host: "example.test", port: 22, user: "root", auth_method: "key", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 1, updated_at: 1 }] };
        if (command === "oars.ai.thread.list") return { ok: true, threads: [] };
        if (command === "oars.ssh.poll") {
          const request = payload as { cursors?: Array<{ channel: number; cursor: number }> };
          return request.cursors?.length
            ? { ok: true, status: "ready", connection_id: 7, channels: [{ id: 9, kind: "exec", command: "rm -rf /tmp/fixture", cursor: 5, dropped: 0, pending: 0, eof: true, exit: 0, data: "done\n" }] }
            : { ok: true, status: "ready", connection_id: 7, channels: [] };
        }
        if (command === "oars.ai.turn.start") return { ok: true, thread_id: "ait-1", turn_id: "air-1", state: "queued" };
        if (command === "oars.ai.turn.poll") {
          turnPollCount += 1;
          if (turnPollCount === 1) return { ok: true, stream_id: "air-1", cursor: 1, dropped: 0, finished: false, state: "awaiting_approval", events: [{ version: 1, sequence: 0, stream_id: "air-1", type: "proposal.ready", payload: { proposal: { id: "aiprop-1", turn_id: "air-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, provider_revision: 1, context_hash: "a".repeat(64), command: "rm -rf /tmp/fixture", command_sha256: "b".repeat(64), explanation: "Remove the fixture.", model_destructive: false, local_destructive: true, needs_sudo: false, created_at_ms: 10, expires_at_ms: Date.now() + 60_000, state: "awaiting_approval" } } }] };
          return { ok: true, stream_id: "air-1", cursor: 2, dropped: 0, finished: true, state: "completed", events: [] };
        }
        if (command === "oars.ai.proposal.run") return { ok: true, execution_id: "aiexec-1", connection_id: 7, channel: 9, state: "executing" };
        throw new Error(`unexpected command: ${command}`);
      }),
    };

    render(<AiTab serverId="server-one" />);
    const request = await screen.findByRole("textbox", { name: "AI terminal request" });
    fireEvent.change(request, { target: { value: "Remove the fixture" } });
    const ask = screen.getByRole("button", { name: "Ask" }) as HTMLButtonElement;
    expect(ask.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "I reviewed this exact selection" }));
    expect(ask.disabled).toBe(false);
    fireEvent.click(ask);

    const run = await screen.findByRole("button", { name: "Run exact command" }) as HTMLButtonElement;
    expect(run.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /reviewed the destructive warning/i }));
    expect(run.disabled).toBe(false);
    fireEvent.click(run);
    await screen.findByText("done", { exact: false });

    const start = calls.find((call) => call.command === "oars.ai.turn.start");
    expect(start?.payload).toMatchObject({ server_id: "server-one", provider_id: readyProvider.id, context_selection: { os: true, monitor: true } });
    const approved = calls.find((call) => call.command === "oars.ai.proposal.run");
    expect(approved?.payload).toMatchObject({ proposal_id: "aiprop-1", expected_revision: 1, command_sha256: "b".repeat(64), destructive_warning_ack: true });
  });

  it("refreshes context just in time before Ask", async () => {
    const readyProvider: AiProvider = { ...provider, test_status: "passed", tested_at_ms: 10 };
    credentialStatus = "configured";
    let refreshed = false;
    window.zero = {
      invoke: vi.fn(async (command: string, payload?: unknown) => {
        calls.push({ command, payload });
        if (command === "oars.ai.provider.list") return { ok: true, providers: [readyProvider] };
        if (command === "oars.ai.credential.status") return { ok: true, status: "configured" };
        if (command === "oars.ai.context.get") return { ok: true, state: "ready", stale: false, updated_at_ms: 10, context: { server_id: "server-one", os: "Linux", hostname: "fixture", monitor: {}, active_logs: [], partial: false, errors: [], updated_at_ms: 10 } };
        if (command === "oars.ai.context.refresh") {
          refreshed = true;
          return { ok: true, operation_id: "context-before-ask", state: "queued" };
        }
        if (command === "oars.ai.context.poll") return { ok: true, stream_id: "context-before-ask", cursor: 1, dropped: 0, finished: true, state: "ready", events: [] };
        if (command === "oars.servers.list") return { servers: [{ id: "server-one", name: "Fixture", host: "example.test", port: 22, user: "root", auth_method: "key", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 1, updated_at: 1 }] };
        if (command === "oars.ai.thread.list") return { ok: true, threads: [] };
        if (command === "oars.ssh.poll") return { ok: true, status: "ready", channels: [] };
        if (command === "oars.ai.turn.start") {
          if (!refreshed) throw new Error("refresh and review current server context before Ask");
          return { ok: true, thread_id: "ait-1", turn_id: "air-1", state: "queued" };
        }
        if (command === "oars.ai.turn.poll") return { ok: true, stream_id: "air-1", cursor: 1, dropped: 0, finished: true, state: "completed", events: [] };
        throw new Error(`unexpected command: ${command}`);
      }),
    };

    render(<AiTab serverId="server-one" />);
    const request = await screen.findByRole("textbox", { name: "AI terminal request" });
    fireEvent.change(request, { target: { value: "Explain the current load" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "I reviewed this exact selection" }));
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));

    await waitFor(() => expect(calls.some((call) => call.command === "oars.ai.context.refresh")).toBe(true));
    await screen.findByText("completed", { exact: false });
    expect(screen.queryByText(/refresh and review current server context before Ask/i)).toBeNull();
  });

  it("renders a completed assistant reply as a normal chat message", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/?ai=assistant-message");
    const readyProvider: AiProvider = { ...provider, test_status: "passed", tested_at_ms: 10 };
    window.zero = {
      invoke: vi.fn(async (command: string) => {
        if (command === "oars.ai.provider.list") return { ok: true, providers: [readyProvider] };
        if (command === "oars.ai.credential.status") return { ok: true, status: "configured" };
        if (command === "oars.ai.context.get") return { ok: true, state: "ready", stale: false, updated_at_ms: 10, context: { server_id: "server-one", os: "Linux", hostname: "fixture", monitor: {}, active_logs: [], partial: false, errors: [], updated_at_ms: 10 } };
        if (command === "oars.servers.list") return { servers: [{ id: "server-one", name: "Fixture", host: "example.test", port: 22, user: "root", auth_method: "key", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 1, updated_at: 1 }] };
        if (command === "oars.ssh.poll") return { ok: true, status: "ready", channels: [] };
        if (command === "oars.ai.thread.list") return { ok: true, threads: [{ id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, model: readyProvider.model, title: "Inspect load", state: "completed", turn_count: 1, updated_at_ms: 10 }] };
        if (command === "oars.ai.thread.get") return { ok: true, thread: { id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, adapter: readyProvider.adapter, model: readyProvider.model, title: "Inspect load", created_at_ms: 1, updated_at_ms: 10 }, turns: [{ id: "air-1", operation_id: "turn-1", state: "completed", message: "What is using memory?", context_hash: "a".repeat(64), provider_revision: 1, connection_id: 7, execution_id: null, channel: null, execution_cursor: 0, exit_status: null, proposal: null, assistant_message: "The API worker is using most of the available memory.", question: null, question_explanation: null }], turns_start: 0, turn_count: 1, active_proposal: null };
        throw new Error(`unexpected command: ${command}`);
      }),
    };

    render(<AiTab serverId="server-one" />);
    await screen.findByText("What is using memory?");
    expect(screen.getByText("The API worker is using most of the available memory.")).toBeTruthy();
    expect(screen.queryByText("Run server command")).toBeNull();
  });

  it("restores a completed command tool and its retained output inside the transcript", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/?ai=assistant-message");
    const readyProvider: AiProvider = { ...provider, test_status: "passed", tested_at_ms: 10 };
    const frozenProposal = { id: "aiprop-1", turn_id: "air-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, provider_revision: 1, context_hash: "a".repeat(64), command: "df -h", command_sha256: "b".repeat(64), explanation: "Inspect mounted filesystem usage.", model_destructive: false, local_destructive: false, needs_sudo: false, created_at_ms: 1, expires_at_ms: 60_000, state: "completed" };
    window.zero = {
      invoke: vi.fn(async (command: string, payload?: unknown) => {
        if (command === "oars.ai.provider.list") return { ok: true, providers: [readyProvider] };
        if (command === "oars.ai.credential.status") return { ok: true, status: "configured" };
        if (command === "oars.ai.context.get") return { ok: true, state: "ready", stale: false, updated_at_ms: 10, context: { server_id: "server-one", os: "Linux", hostname: "fixture", monitor: {}, active_logs: [], partial: false, errors: [], updated_at_ms: 10 } };
        if (command === "oars.servers.list") return { servers: [{ id: "server-one", name: "Fixture", host: "example.test", port: 22, user: "root", auth_method: "key", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 1, updated_at: 1 }] };
        if (command === "oars.ssh.poll") {
          const request = payload as { cursors?: Array<{ channel: number; cursor: number }> };
          return request.cursors?.length ? { ok: true, status: "ready", connection_id: 7, channels: [{ id: 9, kind: "exec", command: "df -h", cursor: 18, dropped: 0, pending: 0, eof: true, exit: 0, data: "/dev/sda1 56% /\n" }] } : { ok: true, status: "ready", connection_id: 7, channels: [] };
        }
        if (command === "oars.ai.thread.list") return { ok: true, threads: [{ id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, model: readyProvider.model, title: "Inspect disk", state: "completed", turn_count: 1, updated_at_ms: 10 }] };
        if (command === "oars.ai.thread.get") return { ok: true, thread: { id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, adapter: readyProvider.adapter, model: readyProvider.model, title: "Inspect disk", created_at_ms: 1, updated_at_ms: 10 }, turns: [{ id: "air-1", operation_id: "turn-1", state: "completed", message: "How full is the disk?", context_hash: "a".repeat(64), provider_revision: 1, connection_id: 7, execution_id: "aiexec-1", channel: 9, execution_cursor: 18, exit_status: 0, proposal: frozenProposal, assistant_message: null, question: null, question_explanation: null }], turns_start: 0, turn_count: 1, active_proposal: null };
        throw new Error(`unexpected command: ${command}`);
      }),
    };

    render(<AiTab serverId="server-one" />);
    await screen.findByRole("region", { name: "Run server command: Completed" });
    expect(screen.getByText("df -h")).toBeTruthy();
    expect(await screen.findByText("/dev/sda1 56% /", { exact: false })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Explain this result" })).toBeTruthy();
  });

  it("renders preamble message above tool proposal and triggers Explain this result", async () => {
    const readyProvider: AiProvider = { ...provider, tool_mode: "native_function", test_status: "passed", tested_at_ms: 10 };
    credentialStatus = "configured";
    let turnPollCount = 0;
    let summarized = false;
    window.zero = {
      invoke: vi.fn(async (command: string, payload?: unknown) => {
        calls.push({ command, payload });
        if (command === "oars.ai.provider.list") return { ok: true, providers: [readyProvider] };
        if (command === "oars.ai.credential.status") return { ok: true, status: "configured" };
        if (command === "oars.ai.context.get") return { ok: true, state: "ready", stale: false, updated_at_ms: 10, context: { server_id: "server-one", os: "Linux", hostname: "fixture", monitor: {}, active_logs: [], partial: false, errors: [], updated_at_ms: 10 } };
        if (command === "oars.ai.context.refresh") return { ok: true, operation_id: "context-refresh", state: "queued" };
        if (command === "oars.ai.context.poll") return { ok: true, stream_id: "context-refresh", cursor: 1, dropped: 0, finished: true, state: "ready", events: [] };
        if (command === "oars.servers.list") return { servers: [{ id: "server-one", name: "Fixture", host: "example.test", port: 22, user: "root", auth_method: "key", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 1, updated_at: 1 }] };
        if (command === "oars.ai.thread.list") return { ok: true, threads: [{ id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, model: readyProvider.model, title: "Check disk", state: "completed", turn_count: 1, updated_at_ms: 10 }] };
        if (command === "oars.ai.thread.get") return {
          ok: true,
          thread: { id: "ait-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, adapter: readyProvider.adapter, model: readyProvider.model, title: "Check disk", created_at_ms: 1, updated_at_ms: 10 },
          turns: [{ id: "air-1", operation_id: "turn-1", state: "completed", message: "Check disk usage", context_hash: "a".repeat(64), provider_revision: 1, connection_id: 7, execution_id: "aiexec-1", channel: 9, execution_cursor: 20, exit_status: 0, proposal: { id: "aiprop-1", turn_id: "air-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, provider_revision: 1, context_hash: "a".repeat(64), command: "df -h", command_sha256: "b".repeat(64), explanation: "Inspect mounted disk usage.", model_destructive: false, local_destructive: false, needs_sudo: false, created_at_ms: 10, expires_at_ms: Date.now() + 60_000, state: "completed" }, assistant_message: "I will check disk usage for you.", question: null, question_explanation: null }],
          turns_start: 0,
          turn_count: 1,
          active_proposal: null,
        };
        if (command === "oars.ssh.poll") {
          const request = payload as { cursors?: Array<{ channel: number; cursor: number }> };
          return request.cursors?.length
            ? { ok: true, status: "ready", connection_id: 7, channels: [{ id: 9, kind: "exec", command: "df -h", cursor: 20, dropped: 0, pending: 0, eof: true, exit: 0, data: "/dev/sda1 85% /\n" }] }
            : { ok: true, status: "ready", connection_id: 7, channels: [] };
        }
        if (command === "oars.ai.turn.start") return { ok: true, thread_id: "ait-1", turn_id: "air-1", state: "queued" };
        if (command === "oars.ai.turn.poll") {
          turnPollCount += 1;
          if (turnPollCount === 1) {
            return {
              ok: true, stream_id: "air-1", cursor: 1, dropped: 0, finished: false, state: "awaiting_approval",
              events: [
                { version: 1, sequence: 0, stream_id: "air-1", type: "assistant.message", payload: { message: "I will check disk usage for you.", explanation: "" } },
                { version: 1, sequence: 1, stream_id: "air-1", type: "proposal.ready", payload: { proposal: { id: "aiprop-1", turn_id: "air-1", revision: 1, server_id: "server-one", provider_id: readyProvider.id, provider_revision: 1, context_hash: "a".repeat(64), command: "df -h", command_sha256: "b".repeat(64), explanation: "Inspect mounted disk usage.", model_destructive: false, local_destructive: false, needs_sudo: false, created_at_ms: 10, expires_at_ms: Date.now() + 60_000, state: "awaiting_approval", tool_mode: "native_function", provider_call_id: "call_1", tool_name: "run_server_command" } } },
              ],
            };
          }
          if (turnPollCount === 2) return { ok: true, stream_id: "air-1", cursor: 2, dropped: 0, finished: true, state: "completed", events: [] };
          return {
            ok: true, stream_id: "air-2", cursor: 1, dropped: 0, finished: true, state: "completed",
            events: [{ version: 1, sequence: 0, stream_id: "air-2", type: "assistant.message", payload: { message: "Your root partition is 85% full.", explanation: "" } }],
          };
        }
        if (command === "oars.ai.proposal.run") return { ok: true, execution_id: "aiexec-1", connection_id: 7, channel: 9, state: "executing" };
        if (command === "oars.ai.turn.summarize") {
          summarized = true;
          return { ok: true, thread_id: "ait-1", turn_id: "air-2", state: "queued" };
        }
        throw new Error(`unexpected command: ${command}`);
      }),
    };

    render(<AiTab serverId="server-one" />);
    const request = await screen.findByRole("textbox", { name: "AI terminal request" });
    fireEvent.change(request, { target: { value: "Check disk usage" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "I reviewed this exact selection" }));
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));

    // Verify preamble is displayed
    await screen.findByText("I will check disk usage for you.");
    // Run proposal
    const runBtn = await screen.findByRole("button", { name: "Run exact command" });
    fireEvent.click(runBtn);

    // Wait for execution completion
    const explainBtn = await screen.findByRole("button", { name: "Explain this result" });
    fireEvent.click(explainBtn);

    await waitFor(() => expect(summarized).toBe(true));
    const summarizeCall = calls.find((c) => c.command === "oars.ai.turn.summarize");
    expect(summarizeCall?.payload).toMatchObject({
      thread_id: "ait-1",
      execution_id: "aiexec-1",
      output_selection: { start_cursor: 0, end_cursor: 20 },
    });
  });
});
