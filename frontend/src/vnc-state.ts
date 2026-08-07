import type { VncPollResult } from "./types";

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
