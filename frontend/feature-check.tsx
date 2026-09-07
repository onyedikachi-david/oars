import { createRoot } from "react-dom/client";
import { useState } from "react";
import { VaultTab } from "./src/VaultTab";
import { AgentTab } from "./src/AgentTab";
import { HistoryTab } from "./src/HistoryTab";
import { CommandPalette } from "./src/components/CommandPalette";
import type { Server } from "./src/types";
import "./src/index.css";

// Explicitly isolated visual fixture. All native calls terminate here.
const server: Server = { id: "fixture", name: "Preview server", host: "preview.invalid", user: "demo", port: 22, auth_method: "agent", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "", tags: [], via_server_id: null, created_at: 0, updated_at: 0 };
let forwarding = false;
const history = { id: "h1", operation_id: "op1", ts: 1700000000000000000, server_id: server.id, kind: "exec", command: "printf 'Hello from Oars'", exit: 0, duration_ms: 10, output_snippet: "Hello from Oars", redacted: false };
(window as unknown as { zero: { invoke: (command: string, payload: Record<string, unknown>) => Promise<unknown> } }).zero = { invoke: async (command, payload) => {
  if (command === "native-sdk.dialog.saveFile") return "/preview/oars.oarsvault";
  if (command === "native-sdk.dialog.openFile") return ["/preview/import.oarsvault"];
  if (command === "oars.vault.export") return { ok: true, exported: 7, sections: 7 };
  if (command === "oars.vault.import") return { ok: true, preview: { errors: [], reports: [{ name: "servers", incoming: 2, new: 1, updated: 1, conflicts: [{ key: "servers:fixture", reason: "Host changed; local credentials cannot be reused" }] }] } };
  if (command === "oars.vault.importConfirm") return { ok: true, result: { notes: ["Preview fixture applied. No files were written."] } };
  if (command === "oars.agent.list") return { ok: true, identities: [{ kind: "ssh-ed25519", fingerprint_sha256: "SHA256:preview-identity", comment: "Preview laptop key" }] };
  if (command === "oars.agent.forward") { forwarding = Boolean(payload.on); return { ok: true }; }
  if (command === "oars.ssh.poll") return { ok: true, status: "ready", forwarding, channels: [{ id: 1, kind: "exec", data: "Hello from Oars", cursor: 15, dropped: 0, pending: 0, eof: true, exit: 0 }] };
  if (command === "oars.history.list") return { ok: true, entries: [history] };
  if (command === "oars.audit.list") return { ok: true, entries: [] };
  if (command === "oars.history.replay") return { ok: true, channel: 1 };
  if (command === "oars.audit.clear") return { ok: true };
  if (command === "oars.servers.list") return { servers: [server] };
  throw new Error(`Unsupported fixture command: ${command}`);
} };
function Fixture() {
  const [view, setView] = useState("Vault"); const [palette, setPalette] = useState(false);
  return <main style={{ maxWidth: 840, margin: "0 auto", height: "100vh", overflow: "auto" }}>
    <header style={{ padding: 16 }}><h1>Feature check — simulated data</h1><p>No server connections, file writes or credential changes occur in this fixture.</p><nav style={{ display: "flex", gap: 16 }}>{["Vault", "Agent", "History"].map(item => <button key={item} onClick={() => setView(item)}>{item}</button>)}<button onClick={() => setPalette(true)}>Palette</button></nav></header>
    {view === "Vault" ? <VaultTab /> : view === "Agent" ? <AgentTab server={server} /> : <HistoryTab />}
    {palette && <CommandPalette onClose={() => setPalette(false)} commands={[{ id: "fixture-server", title: "Preview server", mode: "server", run: () => setView("Agent") }, { id: "fixture-history", title: history.command, mode: "history", run: () => setView("History") }, { id: "fixture-vault", title: "Open Vault", mode: "action", run: () => setView("Vault") }]} />}
  </main>;
}
createRoot(document.getElementById("root")!).render(<Fixture />);
