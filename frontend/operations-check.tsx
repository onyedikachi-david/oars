import { createRoot } from "react-dom/client";
import App from "./src/App";
import "react-mosaic-component/react-mosaic-component.css";
import "./src/index.css";
import type { Server } from "./src/types";

// Isolated fixture: run with operations-check.config.js. Never replace the native bridge.
if (!import.meta.env.OARS_OPERATIONS_FIXTURE) throw new Error("Run this fixture with operations-check.config.js.");
const base: Server = { id: "preview", name: "Backend", host: "backend.example.test", user: "deploy", port: 22, auth_method: "agent", key_path: "", key_has_passphrase: false, host_fingerprint: null, group: "Production", tags: [], via_server_id: null, created_at: 0, updated_at: 0 };
const servers = [base, { ...base, id: "worker", name: "Worker", host: "worker.example.test" }, { ...base, id: "staging", name: "Staging", host: "staging.example.test", group: "Staging" }];
const now = Date.now();
const commands = ["systemctl status nginx --no-pager", "df -h /", "journalctl -u api --since '10 minutes ago'", "npm run deploy", "TOKEN=•••• ./deploy.sh", "uname -a"];
const entries = commands.map((command, index) => ({ id: `h${index}`, operation_id: `op${index}`, server_id: base.id, ts: (now - index * 300000) * 1e6, kind: index === 3 ? "script" : "exec", command, exit: index === 3 ? 1 : 0, duration_ms: index === 3 ? 4210 : 120 + index * 10, output_snippet: index === 3 ? "Build failed: missing configuration.\nNo changes were deployed." : "Command finished successfully.\nDetails are available in this recorded output preview.", redacted: index === 4 }));
let sample = 0;
let forwarding = false;
(window as any).__oarsOperationsBridge = { invoke: async (command: string, payload: any) => {
  if (command === "native-sdk.dialog.saveFile") return "/preview/oars.oarsvault";
  if (command === "native-sdk.dialog.openFile") return ["/preview/import.oarsvault"];
  if (command === "oars.vault.export") return { ok: true, exported: 7, sections: 7 };
  if (command === "oars.vault.import") return { ok: true, preview: { errors: [], reports: [{ name: "servers", incoming: 3, new: 1, updated: 2, conflicts: [{ key: "servers:preview", reason: "Server address differs from the local profile" }] }, { name: "scripts", incoming: 4, new: 4, updated: 0, conflicts: [] }, { name: "history", incoming: 28, new: 28, updated: 0, conflicts: [] }] } };
  if (command === "oars.vault.importConfirm") return { ok: true, result: { notes: ["Simulated import completed."] } };
  if (command === "oars.agent.list") return { ok: true, identities: [{ kind: "ssh-ed25519", comment: "Workstation", fingerprint_sha256: "SHA256:example-public-fingerprint-for-workstation" }, { kind: "ssh-ed25519", comment: "Deployment key", fingerprint_sha256: "SHA256:example-public-fingerprint-for-deployment" }] };
  if (command === "oars.agent.forward") { forwarding = Boolean(payload.on); return { ok: true }; }
  if (command === "oars.vnc.probe") { await new Promise(resolve => setTimeout(resolve, 1500)); return { ok: true, display_present: payload.display === 0, display_accessible: payload.display !== 0, display_managed: payload.display !== 0, x11vnc: true, tigervnc: false, desktop_installed: true, desktop_running: false, window_manager_running: false, desktop_surface_running: false, desktop_panel_running: false, desktop_name: "XFCE", setup_state: "ready", listeners_checked: true, listening: [] }; }
  if (command === "oars.vnc.setup") return { ok: true, action: "configure", executed: false, plan: "", hint: "Simulated start of XFCE and x11vnc on the selected display with password authentication and loopback binding.", desktop_action: "start", desktop_name: "XFCE" };
  if (command === "oars.servers.list") return { servers };
  if (command === "oars.history.list") return { ok: true, entries };
  if (command === "oars.audit.list") return { ok: true, entries: ["backup.operation.terminal", "backup.operation.admitted", "ai.turn.summarize"].map((type, index) => ({ id: `a${index}`, ts: (now - index * 60000) * 1e6, type, target: "Backend", commands: "", detail: "Recorded operation details remain available here.", result: "ok" })) };
  if (command === "oars.scripts.list") return { scripts: [] };
  if (command === "oars.ssh.poll") return { ok: true, status: payload.server_id === "worker" ? "closed" : "ready", connection_id: 1, forwarding, history_full: false, channels: [{ id: 0, kind: "shell", data: "", command: "", cursor: 0, dropped: 0, pending: 0, eof: false, exit: null }, { id: 1, kind: "exec", user_visible: false, command: "internal log scan", data: "internal", cursor: 8, dropped: 0, pending: 0, eof: true, exit: 0 }, { id: 2, kind: "exec", user_visible: true, command: "systemctl status nginx", data: "nginx.service — active (running)\n", cursor: 33, dropped: 0, pending: 0, eof: true, exit: 0 }] };
  if (command === "oars.ssh.connect" || command === "oars.ssh.disconnect" || command === "oars.ssh.resize") return { ok: true };
  if (command === "oars.monitor.poll") { sample++; return { ok: true, ts: Date.now() * 1e6, cpu: { cores: 4, utilization_pct: 22 + 14 * Math.sin(sample / 2), load_1: 0.82, load_5: 0.75, load_15: 0.72, uptime_sec: 480200 }, mem: { total_bytes: 8e9, used_bytes: 4.3e9, available_bytes: 3.7e9, swap_total_bytes: 0, swap_used_bytes: 0 }, disk: { total_bytes: 80e9, used_bytes: 37e9, available_bytes: 43e9 }, processes: [{ pid: 1243, name: "node /srv/api/server.js", cpu: 12.4, mem: 4.2 }, { pid: 981, name: "postgres", cpu: 4.1, mem: 8.7 }, { pid: 1101, name: "nginx: worker process", cpu: 0.4, mem: 0.2 }], probe_error: null }; }
  if (command === "oars.history.shellSetup") return payload.execute ? { ok: true, channel: 2, connection_id: 1 } : { ok: true, command: "# Simulated setup command for visual review only\nmkdir -p ~/.config/oars/shell/v1\nprintf 'Install the reviewed shell helper\\n'", sha256: "fixture-plan", connection_id: 1 };
  if (command === "oars.history.replay") return { ok: true, channel: 2, connection_id: 1 };
  throw new Error(`Unsupported fixture command: ${command}`);
} };
createRoot(document.getElementById("root")!).render(<App />);
