// Browser-only update fixtures. Imported by preview.html, never the shipped app.
import type { UpdateStatus } from "./updates";
const params = new URLSearchParams(window.location.search);
const mode = params.get("updates");
if (mode && window.zero) {
  const original = window.zero.invoke.bind(window.zero);
  let state: UpdateStatus = {
    mode: "sparkle", state: mode === "downloading" ? "downloading" : mode === "verifying" ? "verifying" : mode === "scheduled" ? "blocked" : "available",
    current_version: "0.6.0", latest_version: "0.7.0", error: "", automatic_checks: true, automatic_downloads: true,
    can_check: false, can_install: true, can_resume: mode === "scheduled", can_cancel: mode === "downloading" || mode === "scheduled",
    install_when_idle: mode === "scheduled", busy: mode === "busy" || mode === "scheduled", downloaded_bytes: 17, total_bytes: 100,
    release_notes: "• Check for updates without leaving Oars.\n• Keep working while verified updates download.\n• Choose to restart now or install after active work finishes.",
  };
  window.zero.invoke = async (command, payload) => {
    if (command === "oars.updates.status") return { ...state };
    if (command === "oars.updates.install") {
      const whenIdle = (payload as { when_idle: boolean }).when_idle;
      state = { ...state, state: whenIdle ? "blocked" : "downloading", install_when_idle: whenIdle, can_cancel: true };
      return { ok: true };
    }
    if (command === "oars.updates.cancel") { state = { ...state, state: "idle", install_when_idle: false, can_cancel: false }; return { ok: true }; }
    if (command === "oars.updates.releaseNotes") return { ok: false, error: "This preview uses simulated release notes." };
    return original(command, payload);
  };
  document.title = "Oars update preview — simulated release";
}
