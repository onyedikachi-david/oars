import type { VncPollResult, VncProbeResult } from "./types";

export const VALID_VNC_PORT_MIN = 5900;
export const VALID_VNC_PORT_MAX = 5999;

export function validateVncPort(raw: string): { ok: true; value: number } | { ok: false; message: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, message: "Enter a port between 5900 and 5999" };
  if (!/^\d+$/.test(trimmed)) return { ok: false, message: "Port must be digits only" };
  const value = Number(trimmed);
  if (!Number.isInteger(value) || value < VALID_VNC_PORT_MIN || value > VALID_VNC_PORT_MAX) {
    return { ok: false, message: `Port must be ${VALID_VNC_PORT_MIN}-${VALID_VNC_PORT_MAX}` };
  }
  return { ok: true, value };
}

export function legacyVncAuthWarning(types: string[]): boolean {
  return types.length === 1 && types[0] === "password";
}

export function closedTunnelReason(result: Pick<VncPollResult, "state" | "error">): string | null {
  if (result.state !== "closed") return null;
  return result.error || "The VNC tunnel closed";
}

export function validateSetupPasswords(password: string, confirmation: string): string | null {
  if (!password) return "Enter a VNC password";
  if (password !== confirmation) return "Passwords do not match";
  return null;
}

export function desktopProbeLabel(result: Pick<VncProbeResult, "desktop_installed" | "window_manager_running" | "desktop_surface_running" | "desktop_panel_running" | "desktop_running" | "desktop_name" | "display_present" | "display_accessible" | "display_managed">, display: number): string {
  const installed = result.desktop_installed ? `${result.desktop_name || "Desktop"} installed` : "not installed";
  if (result.display_present && result.display_accessible === false) return `${installed} · display :${display} in use (X authorization required)`;
  if (result.display_present && result.display_managed === false && !result.desktop_running) return `${installed} · display :${display} active (existing X session)`;
  if (result.desktop_installed && result.window_manager_running && !result.desktop_running) {
    const missing = [
      !result.desktop_surface_running ? "desktop" : null,
      !result.desktop_panel_running ? "panel" : null,
    ].filter(Boolean).join(" and ");
    return `${installed} · display :${display} incomplete${missing ? ` (missing ${missing})` : ""}`;
  }
  return `${installed} · display :${display} ${result.desktop_running ? "running" : "stopped"}`;
}
