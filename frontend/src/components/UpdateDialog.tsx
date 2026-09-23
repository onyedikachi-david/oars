import { useEffect, useId, useState } from "react";
import { ArrowRight, ArrowUpRight, Download, ShieldCheck, X } from "lucide-react";
import { ApplicationNotice, ApplicationOverlay } from "./ApplicationPortal";
import { useModalFocus } from "./useModalFocus";
import { Button } from "./ui/button";
import { updateApi, useUpdates, type UpdateStatus } from "../updates";

/* Update flow: use Oars' existing dialog, semantic colors and app icon.
 * The version change and signed release notes lead; two explicit choices sit
 * below. Downloads move to a small notice so the workspace stays usable.
 * Closing the dialog dismisses presentation, never a scheduled installation.
 */
import appIcon from "../../../assets/icon.png";
const actionableStates = ["available", "ready", "blocked"];
export function downloadPercent(status: UpdateStatus): number | undefined {
  if (!Number.isFinite(status.total_bytes) || status.total_bytes <= 0 || !Number.isFinite(status.downloaded_bytes)) return undefined;
  return Math.min(100, Math.max(0, Math.floor(status.downloaded_bytes / status.total_bytes * 100)));
}
function DownloadProgress({ status }: { status: UpdateStatus }) {
  const value = status.state === "downloading" ? downloadPercent(status) : undefined;
  return <div className="update-progress-row"><progress aria-label={status.state === "verifying" ? "Verifying update" : "Download progress"} max={100} value={value} /><span>{value === undefined ? status.state === "verifying" ? "Verifying…" : "Downloading…" : `${value}%`}</span></div>;
}
export function UpdateDialog({ status, onClose, onAction, pending, error }: {
  status: UpdateStatus; onClose: () => void; onAction: (whenIdle: boolean) => void; pending: boolean; error: string;
}) {
  const id = useId();
  const [notesError, setNotesError] = useState("");
  const ref = useModalFocus(onClose);
  const transferring = status.state === "downloading" || status.state === "verifying";
  return <ApplicationOverlay quiet onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <div ref={ref} className="update-dialog" role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} aria-describedby={`${id}-description`}>
      <Button className="update-dialog-close" variant="ghost" size="icon-sm" aria-label="Close update dialog" onClick={onClose}><X /></Button>
      <span className="update-brand-icon"><img src={appIcon} alt="" width={78} height={78} /></span>
      <h2 id={`${id}-title`}>Oars {status.latest_version} is {status.state === "ready" ? "ready to install" : "available"}</h2>
      <p id={`${id}-description`} className="update-dialog-description">{status.install_when_idle ? "Oars will restart after your active work finishes and all sessions are disconnected." : "Install this update now, or let Oars wait until your work is finished."}</p>
      <div className="update-version-change" aria-label={`Version ${status.current_version} to ${status.latest_version}`}><span>{status.current_version}</span><ArrowRight aria-hidden="true" /><strong>{status.latest_version}</strong></div>
      <section className="update-release-summary" aria-labelledby={`${id}-notes`}><h3 id={`${id}-notes`}>What’s new</h3>{status.release_notes ? <p>{status.release_notes}</p> : <p>Release notes aren’t included with this update.</p>}<Button variant="link" size="sm" onClick={() => { setNotesError(""); void updateApi.releaseNotes().catch(() => setNotesError("Could not open release notes. Try again.")); }}>Full release notes <ArrowUpRight data-icon="inline-end" /></Button></section>
      {transferring && <DownloadProgress status={status} />}
      {status.busy && <p className="update-dialog-hint">Finish active work and disconnect sessions before restarting. You can choose “Install when idle” now.</p>}
      <div className="update-dialog-actions">
        <Button disabled={pending || status.busy || !status.can_install || transferring} onClick={() => onAction(false)}>Install and restart</Button>
        <Button variant="outline" disabled={pending || status.install_when_idle || (!status.can_install && !transferring)} onClick={() => onAction(true)}>{status.install_when_idle ? "Waiting for idle" : "Install when idle"}</Button>
      </div>
      {(error || notesError) && <p className="oars-form-error" role="alert">{error || notesError}</p>}
      <p className="update-dialog-footnote"><ShieldCheck aria-hidden="true" />Updates are verified before installation.</p>
    </div>
  </ApplicationOverlay>;
}
export function UpdateExperience({ onOpen }: { onOpen: () => void }) {
  const status = useUpdates();
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const show = () => { setError(""); setOpen(true); };
    window.addEventListener("oars:show-update", show);
    return () => window.removeEventListener("oars:show-update", show);
  }, []);
  useEffect(() => {
    if (status?.mode === "sparkle" && status.latest_version && actionableStates.includes(status.state) && !status.install_when_idle && seen !== status.latest_version) {
      setSeen(status.latest_version); setOpen(true);
    }
  }, [status?.mode, status?.state, status?.latest_version, status?.install_when_idle, seen]);
  async function act(action: () => Promise<unknown>, close = false) {
    setPending(true); setError("");
    try { await action(); if (close) setOpen(false); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not update Oars. Try again."); }
    finally { setPending(false); }
  }
  if (!status || status.mode === "unavailable") return null;
  const transferring = status.state === "downloading" || status.state === "verifying";
  const visible = transferring || status.install_when_idle || actionableStates.includes(status.state) || status.state === "error";
  const mac = status.mode === "sparkle";
  const title = status.state === "error" ? "Update interrupted" : transferring ? `${status.state === "verifying" ? "Verifying" : "Downloading"} Oars ${status.latest_version}` : status.install_when_idle ? "Update scheduled" : `Oars ${status.latest_version} is available`;
  return <>
    {open && mac && status.latest_version && visible && status.state !== "error" && <UpdateDialog status={status} pending={pending} error={error} onClose={() => setOpen(false)} onAction={whenIdle => void act(() => updateApi.install(whenIdle), true)} />}
    {visible && !(open && mac && status.state !== "error") && <ApplicationNotice><section className="update-download-notice" aria-label="Oars update">
      <div className="update-download-heading"><Download aria-hidden="true" /><div><strong>{title}</strong><p>{status.state === "error" ? status.error || "Check for updates to try again." : status.install_when_idle ? "Oars will restart when active work finishes and sessions are disconnected." : transferring ? "You can keep working while the update downloads." : "Review what’s new and choose when to update."}</p></div></div>
      {transferring && <DownloadProgress status={status} />}
      <div className="update-download-actions"><span>Keep using {status.current_version}</span>{status.can_cancel ? <Button variant="outline" size="sm" disabled={pending} onClick={() => void act(updateApi.cancel)}>{status.state === "downloading" ? "Cancel download" : "Cancel scheduled install"}</Button> : <Button variant="outline" size="sm" disabled={pending} onClick={() => { if (status.state === "error") void act(updateApi.check); else if (mac) { setError(""); setOpen(true); } else onOpen(); }}>{status.state === "error" ? "Try again" : "View update"}</Button>}</div>
      {error && <p className="oars-form-error" role="alert">{error}</p>}
    </section></ApplicationNotice>}
  </>;
}
