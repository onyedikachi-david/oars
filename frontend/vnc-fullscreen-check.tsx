import { createRoot } from "react-dom/client";
import { VncTab } from "./src/VncTab";
import "./src/index.css";

// Visual fixture only. No SSH or VNC connection can be opened from this page.
const host = window as unknown as { zero?: { invoke: (command: string) => Promise<unknown> } };
if (!host.zero) host.zero = {
  invoke: async command => {
    if (command === "oars.vnc.probe") return { ok: true, x11vnc: true, tigervnc: false, desktop_installed: true, desktop_running: true, desktop_name: "XFCE", window_manager_running: true, listening: [{ port: 5900, process: "fixture" }] };
    if (command === "oars.vnc.start") return { ok: false, error: "This fixture does not open remote connections." };
    if (command === "oars.vnc.stop") return { ok: true };
    throw new Error(`Fixture does not support ${command}`);
  },
};
document.getElementById("fixture-error")!.textContent = `Fullscreen: enabled=${document.fullscreenEnabled}; request=${typeof document.documentElement.requestFullscreen}; prefixed=${typeof (document.documentElement as unknown as { webkitRequestFullscreen?: unknown }).webkitRequestFullscreen}`;
createRoot(document.getElementById("root")!).render(
  <main style={{ height: "100vh", display: "flex", flexDirection: "column", padding: 32 }}>
    <p>VNC full-screen check — simulated desktop, no remote connections.</p>
    <div style={{ display: "flex", flex: 1, minHeight: 0, border: "1px solid var(--border)", overflow: "hidden" }}>
      <VncTab serverId="fullscreen-fixture" />
    </div>
  </main>,
);
