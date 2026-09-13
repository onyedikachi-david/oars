import { useId, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import { Button } from "./ui/button";
import { ApplicationNotice } from "./ApplicationPortal";
import { updateApi, useUpdates, type UpdateStatus } from "../updates";

function statusText(status: UpdateStatus): string {
  switch (status.state) {
    case "unavailable": return "Updates are available in installed release builds.";
    case "checking": return "Checking for updates…";
    case "downloading": return "Downloading the update in the background…";
    case "verifying": return "Verifying the downloaded update…";
    case "ready": return "The update is ready. It will install when you quit Oars.";
    case "blocked": return "Finish active work and disconnect sessions before restarting.";
    case "available": return `Oars ${status.latest_version} is available.`;
    case "error": return status.error || "Could not check for updates. Try again.";
    default: return "Automatic checks run in the background. You can also check now.";
  }
}
export function UpdateSettings() {
  const id = useId();
  const status = useUpdates();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  async function perform(action: () => Promise<unknown>) {
    setPending(true); setError("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : "The update action failed. Try again."); }
    finally { setPending(false); }
  }
  return <>
    <header><h3>Updates</h3><p>{status ? `Installed version: ${status.current_version}` : "Update controls are available in the desktop app."}</p></header>
    {status && <>
      <p role="status" className="prefs-data-note">{statusText(status)}</p>
      {status.mode !== "unavailable" && <fieldset disabled={pending} className="prefs-update-options">
        <legend>Update preferences</legend>
        <label htmlFor={`${id}-checks`}><input id={`${id}-checks`} type="checkbox" checked={status.automatic_checks} onChange={e => void perform(() => updateApi.preferences(e.target.checked, status.automatic_downloads))} /> Check for updates automatically</label>
        {status.mode === "sparkle" && <label htmlFor={`${id}-downloads`}><input id={`${id}-downloads`} type="checkbox" checked={status.automatic_downloads} onChange={e => void perform(() => updateApi.preferences(status.automatic_checks, e.target.checked))} /> Download updates in the background</label>}
      </fieldset>}
      {status.mode === "sparkle" && <p className="prefs-data-note">Downloads do not interrupt your work. Progress and installation choices appear in the update window.</p>}
      {status.mode === "homebrew" && <><p className="prefs-data-note">Homebrew manages this installation. Finish active work and quit Oars, then run:</p><pre className="prefs-update-command">brew update{"\n"}brew upgrade --cask onyedikachi-david/tap/oars</pre></>}
      {status.mode === "manual" && <p className="prefs-data-note">Download the latest Linux package from the releases page. Finish active work and quit Oars before replacing the installed files. Your settings and server data stay in place.</p>}
      <div className="prefs-update-actions">
        <Button variant="outline" disabled={pending || !status.can_check} onClick={() => void perform(updateApi.check)}><RefreshCw data-icon="inline-start" />{status.state === "ready" && status.mode === "sparkle" ? "Review update" : "Check for updates"}</Button>
        {status.can_resume && <Button disabled={pending || status.busy} onClick={() => void perform(updateApi.resume)}>Restart to update</Button>}
        {status.mode !== "unavailable" && <Button variant="ghost" disabled={pending} onClick={() => void perform(updateApi.releaseNotes)}>Release notes</Button>}
      </div>
    </>}
    {error && <p className="oars-form-error" role="alert">{error}</p>}
  </>;
}
export function UpdateNotice({ onOpen }: { onOpen: () => void }) {
  const status = useUpdates();
  const [dismissed, setDismissed] = useState("");
  if (!status || !["available", "ready", "blocked"].includes(status.state) || !status.latest_version || dismissed === status.latest_version) return null;
  return <ApplicationNotice><div className="oars-update-notice" role="status"><Download aria-hidden="true" /><span>{status.state === "blocked" ? "Finish active work and disconnect sessions before updating." : `Oars ${status.latest_version} is available.`}</span><Button size="sm" variant="outline" onClick={onOpen}>View update</Button><Button size="sm" variant="ghost" onClick={() => setDismissed(status.latest_version)}>Later</Button></div></ApplicationNotice>;
}
