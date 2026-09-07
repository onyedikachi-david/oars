import { CircleCheck, CircleOff, ShieldQuestion, TriangleAlert, LoaderCircle } from "lucide-react";
import type { SessionStatus } from "../types";

export function connectionLabel(status?: SessionStatus) {
  if (status === "ready") return "Connected";
  if (status === "error") return "Failed";
  if (status === "needs_trust") return "Verify identity";
  if (status === "connecting" || status === "authenticating") return "Connecting";
  return "Offline";
}

/** Shape and text carry the state; color is supporting information. */
export function ConnectionStatus({ status, label = false }: { status?: SessionStatus; label?: boolean }) {
  const Icon = status === "ready" ? CircleCheck : status === "error" ? TriangleAlert : status === "needs_trust" ? ShieldQuestion : status === "connecting" || status === "authenticating" ? LoaderCircle : CircleOff;
  return <span className={`connection-status connection-status-${status ?? "closed"}`}><Icon aria-hidden="true" />{label && <span>{connectionLabel(status)}</span>}</span>;
}
